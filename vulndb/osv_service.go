// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package vulndb

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
)

// syncSpec describes how to sync one staging table into its live counterpart
// using EXCEPT-based set operations. The three-step sync (delete removed rows,
// insert new rows, update changed rows) makes every import idempotent and
// removes the dependency on lastImportTime for correctness.
type syncSpec struct {
	live    string   // live table name
	stage   string   // staging table name
	keyCols []string // columns forming the row identity (used in EXCEPT queries)

	// When set, rows whose key already exists in live but whose contentHashCol
	// value differs are updated with contentCols values.
	contentHashCol string
	contentCols    []string

	// insertCols lists the columns written on INSERT (must match insertSelectExprs length).
	insertCols []string
	// insertSelectExprs are the corresponding SELECT expressions from the stage table.
	// Use this to apply type casts (e.g. "semver_introduced::semver").
	insertSelectExprs []string
}

// liveTableSpecs defines the sync configuration for every live table.
// Both SyncAllTables (staging→live) and applyQuickDiff (QuickDiff struct→live)
// use these specs so all apply logic lives in one place.
var liveTableSpecs = func() []syncSpec {
	cveAllCols := []string{"id", "content_hash", "cve", "date_published", "date_last_modified", "description", "cvss", `"references"`, "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile", "vector"}
	relAllCols := []string{"target_cve", "source_cve", "relationship_type"}
	acInsertCols := []string{"id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	acInsertExprs := []string{"id", "purl", "ecosystem", "version", "semver_introduced::semver", "semver_fixed::semver", "version_introduced", "version_fixed"}
	pivotAllCols := []string{"affected_component_id", "cve_id"}
	exploitAllCols := []string{"id", "published", "updated", "author", "type", "verified", "source_url", "description", "cve_id", "tags", "forks", "watchers", "subscribers", "stars"}
	malPkgAllCols := []string{"id", "summary", "details", "published", "modified"}
	malCompInsertCols := []string{"id", "malicious_package_id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	malCompInsertExprs := []string{"id", "malicious_package_id", "purl", "ecosystem", "version::text", "semver_introduced::semver", "semver_fixed::semver", "version_introduced", "version_fixed"}
	return []syncSpec{
		{
			live: "cves", stage: "cves_stage", keyCols: []string{"id"},
			contentHashCol: "content_hash",
			contentCols:    []string{"content_hash", "description", "cvss", "vector", "date_published", "date_last_modified", `"references"`},
			insertCols:     cveAllCols, insertSelectExprs: cveAllCols,
		},
		{
			live: "cve_relationships", stage: "cve_relationships_stage",
			keyCols:    []string{"target_cve", "source_cve", "relationship_type"},
			insertCols: relAllCols, insertSelectExprs: relAllCols,
		},
		{
			live: "affected_components", stage: "affected_components_stage",
			keyCols:    []string{"id"},
			insertCols: acInsertCols, insertSelectExprs: acInsertExprs,
		},
		{
			live: "cve_affected_component", stage: "cve_affected_component_stage",
			keyCols:    []string{"cve_id", "affected_component_id"},
			insertCols: pivotAllCols, insertSelectExprs: pivotAllCols,
		},
		{
			live: "exploits", stage: "exploits_stage", keyCols: []string{"id"},
			contentHashCol: "updated",
			contentCols:    []string{"published", "updated", "author", "source_url", "description", "forks", "watchers", "subscribers", "stars"},
			insertCols:     exploitAllCols, insertSelectExprs: exploitAllCols,
		},
		{
			live: "malicious_packages", stage: "mal_pkgs_stage", keyCols: []string{"id"},
			contentHashCol: "modified",
			contentCols:    []string{"summary", "details", "published", "modified"},
			insertCols:     malPkgAllCols, insertSelectExprs: malPkgAllCols,
		},
		{
			live: "malicious_affected_components", stage: "mal_comps_stage",
			keyCols:    []string{"id"},
			insertCols: malCompInsertCols, insertSelectExprs: malCompInsertExprs,
		},
	}
}()

// computeDiffFromStage is Phase 1: builds _diff_del_*, _diff_ins_*, _diff_upd_* temp
// tables by running EXCEPT queries between the live table and its staging counterpart.
// Only AccessShareLock is held on the live table during this phase.
func computeDiffFromStage(ctx context.Context, tx pgx.Tx, spec syncSpec) error {
	keysCSV := strings.Join(spec.keyCols, ", ")
	tmpDel := "_diff_del_" + spec.live
	tmpIns := "_diff_ins_" + spec.live
	tmpUpd := "_diff_upd_" + spec.live

	t := time.Now()

	if _, err := tx.Exec(ctx, fmt.Sprintf(
		`CREATE INDEX ON %s (%s)`, spec.stage, keysCSV,
	)); err != nil {
		return fmt.Errorf("computeDiffFromStage index (%s): %w", spec.live, err)
	}

	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		CREATE TEMP TABLE %s ON COMMIT DROP AS
		SELECT %s FROM %s EXCEPT SELECT %s FROM %s
	`, tmpDel, keysCSV, spec.live, keysCSV, spec.stage)); err != nil {
		return fmt.Errorf("computeDiffFromStage del (%s): %w", spec.live, err)
	}

	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		CREATE TEMP TABLE %s ON COMMIT DROP AS
		SELECT %s FROM %s
		WHERE (%s) IN (SELECT %s FROM %s EXCEPT SELECT %s FROM %s)
	`, tmpIns,
		strings.Join(spec.insertSelectExprs, ", "), spec.stage,
		keysCSV, keysCSV, spec.stage, keysCSV, spec.live,
	)); err != nil {
		return fmt.Errorf("computeDiffFromStage ins (%s): %w", spec.live, err)
	}

	if spec.contentHashCol != "" {
		joinParts := make([]string, len(spec.keyCols))
		for i, k := range spec.keyCols {
			joinParts[i] = fmt.Sprintf("_s.%s = _l.%s", k, k)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			CREATE TEMP TABLE %s ON COMMIT DROP AS
			SELECT _s.* FROM %s _s JOIN %s _l ON %s WHERE _l.%s != _s.%s
		`, tmpUpd, spec.stage, spec.live,
			strings.Join(joinParts, " AND "),
			spec.contentHashCol, spec.contentHashCol,
		)); err != nil {
			return fmt.Errorf("computeDiffFromStage upd (%s): %w", spec.live, err)
		}
	}

	slog.Info("syncTable: diff computed", "table", spec.live, "took", time.Since(t))
	return nil
}

// applyDiff is Phase 2: applies the pre-populated _diff_del_*, _diff_ins_*, _diff_upd_*
// temp tables to the live table. The RowExclusiveLock window is limited to this phase.
// These temp tables are created by either computeDiffFromStage or computeDiffFromQuickDiff.
func applyDiff(ctx context.Context, tx pgx.Tx, spec syncSpec) (deleted, inserted, updated int64, lockHeld time.Duration, err error) {
	tmpDel := "_diff_del_" + spec.live
	tmpIns := "_diff_ins_" + spec.live
	tmpUpd := "_diff_upd_" + spec.live
	lockStart := time.Now()

	whereJoin := make([]string, len(spec.keyCols))
	for i, k := range spec.keyCols {
		whereJoin[i] = fmt.Sprintf("%s.%s = %s.%s", spec.live, k, tmpDel, k)
	}
	t := time.Now()
	tag, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s USING %s WHERE %s`,
		spec.live, tmpDel, strings.Join(whereJoin, " AND ")))
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("applyDiff delete (%s): %w", spec.live, err)
	}
	deleted = tag.RowsAffected()
	slog.Info("syncTable: delete", "table", spec.live, "deleted", deleted, "took", time.Since(t))

	t = time.Now()
	tag, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`,
		spec.live,
		strings.Join(spec.insertCols, ", "),
		strings.Join(spec.insertSelectExprs, ", "),
		tmpIns,
	))
	if err != nil {
		return deleted, 0, 0, 0, fmt.Errorf("applyDiff insert (%s): %w", spec.live, err)
	}
	inserted = tag.RowsAffected()
	slog.Info("syncTable: insert", "table", spec.live, "inserted", inserted, "took", time.Since(t))

	if spec.contentHashCol != "" && len(spec.contentCols) > 0 {
		setClauses := make([]string, len(spec.contentCols))
		for i, c := range spec.contentCols {
			setClauses[i] = fmt.Sprintf("%s = %s.%s", c, tmpUpd, c)
		}
		joinCond := make([]string, len(spec.keyCols))
		for i, k := range spec.keyCols {
			joinCond[i] = fmt.Sprintf("%s.%s = %s.%s", spec.live, k, tmpUpd, k)
		}
		t = time.Now()
		tag, err = tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s FROM %s WHERE %s`,
			spec.live,
			strings.Join(setClauses, ", "),
			tmpUpd,
			strings.Join(joinCond, " AND "),
		))
		if err != nil {
			return deleted, inserted, 0, 0, fmt.Errorf("applyDiff update (%s): %w", spec.live, err)
		}
		updated = tag.RowsAffected()
		slog.Info("syncTable: update", "table", spec.live, "updated", updated, "took", time.Since(t))
	}

	lockHeld = time.Since(lockStart)
	slog.Info("syncTable: lock released", "table", spec.live, "lock_held", lockHeld)
	return deleted, inserted, updated, lockHeld, nil
}

func liveTableIsEmpty(ctx context.Context, tx pgx.Tx, live string) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s LIMIT 1)`, live)).Scan(&exists); err != nil {
		return false, fmt.Errorf("could not check whether %s is empty: %w", live, err)
	}
	return !exists, nil
}

func insertStageIntoLive(ctx context.Context, tx pgx.Tx, spec syncSpec) (inserted int64, lockHeld time.Duration, err error) {
	t := time.Now()
	tag, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`,
		spec.live,
		strings.Join(spec.insertCols, ", "),
		strings.Join(spec.insertSelectExprs, ", "),
		spec.stage,
	))
	if err != nil {
		return 0, 0, fmt.Errorf("insertStageIntoLive (%s): %w", spec.live, err)
	}
	inserted = tag.RowsAffected()
	lockHeld = time.Since(t)
	slog.Info("syncTable: fast path insert", "table", spec.live, "inserted", inserted, "took", lockHeld)
	return inserted, lockHeld, nil
}

// syncTable is the thin wrapper used by SyncAllTables: compute diff from staging, then apply.
func syncTable(ctx context.Context, tx pgx.Tx, spec syncSpec) (deleted, inserted, updated int64, lockHeld time.Duration, err error) {
	empty, err := liveTableIsEmpty(ctx, tx, spec.live)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("syncTable live check (%s): %w", spec.live, err)
	}
	if empty {
		inserted, lockHeld, err = insertStageIntoLive(ctx, tx, spec)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		return 0, inserted, 0, lockHeld, nil
	}
	if err = computeDiffFromStage(ctx, tx, spec); err != nil {
		return
	}
	return applyDiff(ctx, tx, spec)
}

// SyncAllTables syncs every staging table into its live counterpart using
// EXCEPT-based set operations. It replaces the old flush functions and makes
// every import fully idempotent regardless of import history.
func SyncAllTables(ctx context.Context, tx pgx.Tx) error {
	start := time.Now()
	var totalLock time.Duration
	for _, spec := range liveTableSpecs {
		_, _, _, lock, err := syncTable(ctx, tx, spec)
		if err != nil {
			return err
		}
		totalLock += lock
	}
	slog.Info("finished syncing all tables", "took", time.Since(start), "total_lock_held", totalLock)
	return nil
}

type osvService struct {
	httpClient                *http.Client
	affectedCmpRepository     shared.AffectedComponentRepository
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	pool                      *pgxpool.Pool
}

func NewOSVService(affectedCmpRepository shared.AffectedComponentRepository, cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository, pool *pgxpool.Pool) osvService {
	return osvService{
		httpClient:                &http.Client{},
		affectedCmpRepository:     affectedCmpRepository,
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		pool:                      pool,
	}
}

var osvBaseURL string = "https://storage.googleapis.com/osv-vulnerabilities"

var importEcosystems = []string{
	"Go",
	"npm",
	"Alpine",
	"Bitnami",
	"crates.io",
	"Debian",
	"GIT",
	"Maven",
	"NuGet",
	"Packagist",
	"PyPI",
	"RubyGems",
	"Red Hat",
}

var ignoreVulnerabilityEcosystems = []string{
	"CGA",
	"GSD",
	"OSV",
}

type cveAffectedComponentRow struct {
	CveID               int64 `gorm:"column:cve_id"`
	AffectedComponentID int64 `gorm:"column:affected_component_id"`
}

type vulndbRows struct {
	CVEs                  []models.CVE
	CVERelationships      []models.CVERelationship
	AffectedComponents    []models.AffectedComponent
	CVEAffectedComponents []cveAffectedComponentRow
}

type OSVEntry struct {
	OSV               *dtos.OSV
	ModifiedTimestamp time.Time
}

type zipJob struct {
	File      *zip.File
	Ecosystem string
}

const numberOfZipWorkers = 10
const debugLocalZip = false // set to true to read the zip files from disk instead of fetching them from the network; useful for debugging and development to speed up the import process

var deduplicateCveMap = sync.Map{} // map[string]struct{} to track already processed CVE IDs and avoid duplicates

// fetchAndImportOSV fetches all OSV vulnerabilities from the network, writes them to the
// database via tx, runs cleanup, and returns the surviving entries plus surviving CVE IDs.
// The caller is responsible for Begin/Commit/Rollback on tx.
func (s osvService) fetchAndImportOSV(ctx context.Context, tx pgx.Tx, importStart time.Time) ([]OSVEntry, map[string]struct{}, error) {
	zipPushWaitGroup := &sync.WaitGroup{}
	zipWorkWaitGroup := &sync.WaitGroup{}

	var fetchFailures atomic.Int64

	zipJobs := make(chan zipJob, 10_000)
	vulnData := make(chan OSVEntry, 5000)

	// start all zip workers which process individual zip files
	for range numberOfZipWorkers {
		zipWorkWaitGroup.Add(1)
		go s.zipWorkerFunction(zipWorkWaitGroup, zipJobs, vulnData, importStart, &fetchFailures)
	}

	// start the fetching controller which's job is to call the fetching functions for each ecosystem
	zipPushWaitGroup.Add(1)
	go s.fetchingController(zipPushWaitGroup, zipJobs, &fetchFailures)

	// when all zip files are pushed we do not receive more zip jobs
	go func() {
		zipPushWaitGroup.Wait()
		close(zipJobs)
	}()

	// when all zips got processed we get no more osv vulns
	go func() {
		zipWorkWaitGroup.Wait()
		close(vulnData)
	}()

	// collect all osv vulns from the zip workers
	allOSVVulns := make([]OSVEntry, 0, 200_000)
	for entry := range vulnData {
		allOSVVulns = append(allOSVVulns, entry)
	}

	// check if we ran into any errors while fetching
	if n := fetchFailures.Load(); n > 0 {
		return nil, nil, fmt.Errorf("aborting export: %d ids could not be fetched; will retry on next run", n)
	}

	// double check if we could fetch any data at all
	if len(allOSVVulns) == 0 {
		return nil, nil, fmt.Errorf("could not fetch any OSV vulns")
	}

	// sort the slice so the import is able to fast exit after hitting the last timestamp
	slices.SortFunc(allOSVVulns, func(v1, v2 OSVEntry) int {
		return -v1.ModifiedTimestamp.Compare(v2.ModifiedTimestamp)
	})

	slog.Info("fetched OSV vulns and malware", "entries", len(allOSVVulns), "latest", allOSVVulns[0].ModifiedTimestamp.Format(time.DateTime))

	if err := PrepareBulkInsert(ctx, tx); err != nil {
		return nil, nil, fmt.Errorf("could not prepare bulk insert: %w", err)
	}
	if err := CreateStagingTables(ctx, tx); err != nil {
		return nil, nil, fmt.Errorf("could not create staging tables: %w", err)
	}
	malRows := gobOSVToMalTransformer(allOSVVulns)
	vulnRows := gobOSVToVulnTransformer()(allOSVVulns)
	fakeRows, fakeComps, osvEntries := buildFakePackages()
	// add the fake packages to the allOSVVulns - that is the gob file we are writing to disk for the import, so it needs to contain all entries, including the fake ones.
	allOSVVulns = append(allOSVVulns, osvEntries...)
	malRows.pkgs = append(malRows.pkgs, fakeRows...)
	malRows.comps = append(malRows.comps, fakeComps...)
	if err := InsertCVEsBulk(ctx, tx, vulnRows.CVEs, "cves_stage"); err != nil {
		return nil, nil, fmt.Errorf("could not insert cves: %w", err)
	}
	if err := InsertCVERelationshipsBulk(ctx, tx, vulnRows.CVERelationships, "cve_relationships_stage"); err != nil {
		return nil, nil, fmt.Errorf("could not insert cve relationships: %w", err)
	}
	if err := insertAffectedComponentsBulk(ctx, tx, vulnRows.AffectedComponents, "affected_components_stage"); err != nil {
		return nil, nil, fmt.Errorf("could not insert affected components: %w", err)
	}
	if err := insertCVEAffectedComponentsBulk(ctx, tx, vulnRows.CVEAffectedComponents, "cve_affected_component_stage"); err != nil {
		return nil, nil, fmt.Errorf("could not insert cve affected components: %w", err)
	}
	if err := insertMaliciousPackagesBulk(ctx, tx, malRows.pkgs, malRows.comps, "mal_pkgs_stage", "mal_comps_stage"); err != nil {
		return nil, nil, fmt.Errorf("could not insert malicious packages: %w", err)
	}
	if err := FlushOSVStagingTables(ctx, tx); err != nil {
		return nil, nil, fmt.Errorf("could not flush osv staging tables: %w", err)
	}
	if err := AddIndexesAndConstraints(ctx, tx); err != nil {
		return nil, nil, fmt.Errorf("could not re-add indexes and constraints: %w", err)
	}

	// Delete orphan CVEs and affected_components so the DB state matches what
	// importers will end up with, and so integrity checksums are valid.
	runCleanUpJobs(ctx, tx)

	// Re-query surviving CVE IDs to filter the gob — no point serializing
	// entries that were just deleted.
	survivingRows, err := tx.Query(ctx, `SELECT cve FROM cves;`)
	if err != nil {
		return nil, nil, fmt.Errorf("could not query surviving CVE IDs: %w", err)
	}

	// build a map from the result set, using cursors
	surviving := make(map[string]struct{}, len(allOSVVulns))
	for survivingRows.Next() {
		var id string
		if err := survivingRows.Scan(&id); err != nil {
			survivingRows.Close()
			return nil, nil, fmt.Errorf("could not scan CVE ID: %w", err)
		}
		surviving[id] = struct{}{}
	}

	survivingRows.Close()
	if err := survivingRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating surviving CVE IDs: %w", err)
	}

	// then filter out each OSV object that did not survive the clean up
	kept := allOSVVulns[:0]
	for _, e := range allOSVVulns {
		if _, ok := surviving[e.OSV.ID]; ok || strings.HasPrefix(e.OSV.ID, "MAL-") {
			kept = append(kept, e)
		}
	}
	slog.Info("filtered OSV entries after cleanup", "before", len(vulnRows.CVEs), "after", len(surviving))
	return kept, surviving, nil
}

// starts all zip fetches in the background
func (s osvService) fetchingController(zipPushWaitGroup *sync.WaitGroup, zipJobs chan zipJob, fetchFailures *atomic.Int64) {
	defer zipPushWaitGroup.Done()
	for _, ecosystem := range importEcosystems {
		slog.Info("start fetching zip", "ecosystem", ecosystem)
		zipPushWaitGroup.Add(1)
		go s.fetchEcosystemEntriesViaZip(zipPushWaitGroup, ecosystem, zipJobs, fetchFailures)
	}
	slog.Info("finished starting all downloads")
}

func (s osvService) fetchEcosystemEntriesViaZip(zipPushWaitGroup *sync.WaitGroup, ecosystem string, zipJobs chan zipJob, fetchFailures *atomic.Int64) {
	defer zipPushWaitGroup.Done()
	start := time.Now()

	zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
	if err != nil {
		fetchFailures.Add(1)
		return
	}

	if len(zipReader.File) == 0 {
		fetchFailures.Add(1)
		return
	}

	// filter and push all jobs to the zip worker functions
	for i := range zipReader.File {
		// first check if we want to even include this vuln based on the file name
		if shouldIgnoreVulnerabilityID(zipReader.File[i].Name) {
			continue
		}

		// check each OSV-ID only once even if it appears across different ecosystems
		// warning: we always use the ecosystem of the first occurrence; we assume they are all equal, but its still non-deterministic behavior
		if _, loaded := deduplicateCveMap.LoadOrStore(zipReader.File[i].Name, struct{}{}); loaded {
			continue
		}

		zipJobs <- zipJob{File: zipReader.File[i], Ecosystem: ecosystem}
	}
	slog.Info("finished extracting zip file", "ecosystem", ecosystem, "took", time.Since(start))
}

func (s osvService) getOSVZipContainingEcosystem(ecosystem string) (*zip.Reader, error) {
	if debugLocalZip {
		slog.Info("debug mode enabled, reading zip from disk instead of fetching from network", "ecosystem", ecosystem)
		// check if the file exists on disk and read it if it does, otherwise return an error
		path := fmt.Sprintf("./%s.zip", ecosystem)
		if _, err := os.Stat(path); err != nil {
			// just fall through to download it
			slog.Warn("could not find local zip file, falling back to network fetch", "path", path)
		} else {
			reader, err := zip.OpenReader(path)
			if err == nil {
				slog.Info("successfully opened local zip file", "path", path)
				return &reader.Reader, nil
			}
		}
	}
	req, err := http.NewRequest(http.MethodGet, osvBaseURL+"/"+ecosystem+"/all.zip", nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not download zip")
	}
	if debugLocalZip {
		// use a tee reader to read the response body and write it to a file at the same time for debugging purposes
		path := fmt.Sprintf("./%s.zip", ecosystem)
		outFile, err := os.Create(path)
		if err != nil {
			slog.Warn("could not create local zip file, skipping writing to disk", "path", path, "err", err)
		} else {
			slog.Info("created local zip file for debugging", "path", path)
			tee := io.TeeReader(res.Body, outFile)
			res.Body = io.NopCloser(tee)
		}
	}

	return utils.ZipReaderFromResponse(res)
}

func (s osvService) zipWorkerFunction(zipWorkWaitGroup *sync.WaitGroup, zipJobs chan zipJob, output chan OSVEntry, importStart time.Time, fetchFailures *atomic.Int64) {
	defer zipWorkWaitGroup.Done()
	for job := range zipJobs {
		readCloser, err := job.File.Open()
		if err != nil {
			fetchFailures.Add(1)
			slog.Error("could not open osv file", "file", job.File.Name, "err", err)
			continue
		}

		osvEntry := dtos.OSV{}
		if err = json.NewDecoder(readCloser).Decode(&osvEntry); err != nil {
			readCloser.Close()
			fetchFailures.Add(1)
			slog.Error("could not parse osv file to OSV dto", "file", job.File.Name, "err", err)
			continue
		}
		readCloser.Close()

		if shouldIgnoreVulnerabilityID(osvEntry.ID) {
			continue
		}

		// cut all vulns which are newer than our import start
		if osvEntry.Modified.After(importStart) {
			slog.Warn("ran into race condition on import, skipping vuln with newer information")
			continue
		}
		output <- OSVEntry{OSV: &osvEntry, ModifiedTimestamp: osvEntry.Modified}
	}
}

// InsertCVEsBulk streams cves into the staging table. Call flushStagingTables once after all batches.
func InsertCVEsBulk(ctx context.Context, tx pgx.Tx, cves []models.CVE, table string) error {
	if len(cves) == 0 {
		return nil
	}
	columnNames := []string{"id", "content_hash", "cve", "date_published", "date_last_modified", "description", "cvss", "references", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile", "vector"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columnNames, pgx.CopyFromSlice(len(cves), func(i int) ([]any, error) {
		row := cves[i]
		return []any{row.ID, row.ContentHash, row.CVE, row.DatePublished, row.DateLastModified, row.Description, row.CVSS, row.References, row.CISAExploitAdd, row.CISAActionDue, row.CISARequiredAction, row.CISAVulnerabilityName, row.EPSS, row.Percentile, row.Vector}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve rows into staging table: %w", err)
	}
	return nil
}

// InsertCVERelationshipsBulk streams cve relationships into the staging table. Call flushStagingTables once after all batches.
func InsertCVERelationshipsBulk(ctx context.Context, tx pgx.Tx, cveRelationships []models.CVERelationship, table string) error {
	if len(cveRelationships) == 0 {
		return nil
	}
	columnNames := []string{"target_cve", "source_cve", "relationship_type"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columnNames, pgx.CopyFromSlice(len(cveRelationships), func(i int) ([]any, error) {
		row := cveRelationships[i]
		return []any{row.TargetCVE, row.SourceCVE, row.RelationshipType}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve relationship rows into staging table: %w", err)
	}
	return nil
}

// insertAffectedComponentsBulk streams affected components into the staging table. Call flushStagingTables once after all batches.
// The semver cast (text → semver type) happens in flushStagingTables, not here.
func insertAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, components []models.AffectedComponent, table string) error {
	if len(components) == 0 {
		return nil
	}
	columnNames := []string{"id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columnNames, pgx.CopyFromSlice(len(components), func(i int) ([]any, error) {
		c := components[i]
		return []any{c.ID, c.PurlWithoutVersion, c.Ecosystem, c.Version, c.SemverIntroduced, c.SemverFixed, c.VersionIntroduced, c.VersionFixed}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy affected component rows into staging table: %w", err)
	}
	return nil
}

// insertCVEAffectedComponentsBulk streams pivot rows into the staging table. Call flushStagingTables once after all batches.
func insertCVEAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, pivotRows []cveAffectedComponentRow, table string) error {
	if len(pivotRows) == 0 {
		return nil
	}

	columnNames := []string{"affected_component_id", "cve_id"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columnNames, pgx.CopyFromSlice(len(pivotRows), func(i int) ([]any, error) {
		row := pivotRows[i]
		return []any{row.AffectedComponentID, row.CveID}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve affected component rows into table: %w", err)
	}

	return nil
}

// FlushOSVStagingTables is kept for the bulk import path which truncates live tables
// and then does a simple INSERT from staging (no EXCEPT diff needed on an empty table).
func FlushOSVStagingTables(ctx context.Context, tx pgx.Tx) error {
	start := time.Now()

	if _, err := tx.Exec(ctx, `
		INSERT INTO cves (id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector)
		SELECT id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector
		FROM cves_stage
		ON CONFLICT (id) DO UPDATE SET
			content_hash       = EXCLUDED.content_hash,
			date_published     = EXCLUDED.date_published,
			date_last_modified = EXCLUDED.date_last_modified,
			description        = EXCLUDED.description,
			cvss               = EXCLUDED.cvss,
			vector             = EXCLUDED.vector`); err != nil {
		return fmt.Errorf("could not flush cves: %w", err)
	}
	slog.Info("flushed cves", "took", time.Since(start))

	t := time.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
		SELECT target_cve, source_cve, relationship_type
		FROM cve_relationships_stage
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`); err != nil {
		return fmt.Errorf("could not flush cve_relationships: %w", err)
	}
	slog.Info("flushed cve_relationships", "took", time.Since(t))

	t = time.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO affected_components (id, purl, ecosystem, version, semver_introduced, semver_fixed, version_introduced, version_fixed)
		SELECT id, purl, ecosystem, version,
			semver_introduced::semver, semver_fixed::semver,
			version_introduced, version_fixed
		FROM affected_components_stage`); err != nil {
		return fmt.Errorf("could not flush affected_components: %w", err)
	}
	slog.Info("flushed affected_components", "took", time.Since(t))

	// cve_affected_component must come after affected_components so the FK is satisfied when AddIndexesAndConstraints validates it
	t = time.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_affected_component (affected_component_id, cve_id)
		SELECT affected_component_id, cve_id
		FROM cve_affected_component_stage`); err != nil {
		return fmt.Errorf("could not flush cve_affected_component: %w", err)
	}
	slog.Info("flushed cve_affected_component", "took", time.Since(t))

	t = time.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO malicious_packages (id, summary, details, published, modified)
		SELECT id, summary, details, published, modified FROM mal_pkgs_stage
		ON CONFLICT (id) DO UPDATE SET
			summary   = EXCLUDED.summary,
			details   = EXCLUDED.details,
			published = EXCLUDED.published,
			modified  = EXCLUDED.modified`); err != nil {
		return fmt.Errorf("could not flush malicious_packages: %w", err)
	}
	slog.Info("flushed malicious_packages", "took", time.Since(t))

	t = time.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO malicious_affected_components (id, malicious_package_id, purl, ecosystem, version, semver_introduced, semver_fixed, version_introduced, version_fixed)
		SELECT id, malicious_package_id, purl, ecosystem, version::text,
			semver_introduced::semver, semver_fixed::semver,
			version_introduced, version_fixed
		FROM mal_comps_stage
		ON CONFLICT (id) DO NOTHING`); err != nil {
		return fmt.Errorf("could not flush malicious_affected_components: %w", err)
	}
	slog.Info("flushed malicious_affected_components", "took", time.Since(t))

	slog.Info("finished flushing osv staging tables", "total", time.Since(start))
	return nil
}

// flushNonOSVStagingTables flushes exploits and malicious packages from their staging tables.
func flushNonOSVStagingTables(ctx context.Context, tx pgx.Tx) error {
	t := time.Now()
	// Delete exploits that are no longer in the current fetch so that the live table
	// exactly matches the gob before integrity is computed.
	if _, err := tx.Exec(ctx, `
		DELETE FROM exploits
		WHERE id NOT IN (SELECT id FROM exploits_stage)`); err != nil {
		return fmt.Errorf("could not delete stale exploits: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO exploits (id, published, updated, author, type, verified, source_url, description, cve_id, tags, forks, watchers, subscribers, stars)
		SELECT id, published, updated, author, type, verified, source_url, description, cve_id, tags, forks, watchers, subscribers, stars
		FROM exploits_stage
		ON CONFLICT (id) DO UPDATE SET
			published   = EXCLUDED.published,
			updated     = EXCLUDED.updated,
			author      = EXCLUDED.author,
			source_url  = EXCLUDED.source_url,
			description = EXCLUDED.description,
			forks       = EXCLUDED.forks,
			watchers    = EXCLUDED.watchers,
			subscribers = EXCLUDED.subscribers,
			stars       = EXCLUDED.stars`); err != nil {
		return fmt.Errorf("could not flush exploits: %w", err)
	}
	slog.Info("finished flushing non-osv staging tables (exploits)", "total", time.Since(t))
	return nil
}

func CreateStagingTables(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		CREATE TEMP TABLE IF NOT EXISTS cves_stage (
			id                      bigint,
			content_hash            bigint,
			cve                     text,
			date_published          timestamptz,
			date_last_modified      timestamptz,
			description             text,
			cvss                    numeric(4,2),
			"references"            text,
			cisa_exploit_add        date,
			cisa_action_due         date,
			cisa_required_action    text,
			cisa_vulnerability_name text,
			epss                    numeric(6,5),
			percentile              numeric(6,5),
			vector                  text
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS cve_relationships_stage (
			target_cve        text,
			source_cve        text,
			relationship_type text
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS affected_components_stage (
			id                 bigint,
			purl               text,
			ecosystem          text,
			version            text,
			semver_introduced  text,
			semver_fixed       text,
			version_introduced text,
			version_fixed      text
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS cve_affected_component_stage (
			affected_component_id bigint,
			cve_id                bigint
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS exploits_stage (
			id          text,
			published   date,
			updated     date,
			author      text,
			type        text,
			verified    boolean,
			source_url  text,
			description text,
			cve_id      text,
			tags        text,
			forks       integer,
			watchers    integer,
			subscribers integer,
			stars       integer
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS mal_pkgs_stage (
			id        text,
			summary   text,
			details   text,
			published timestamptz,
			modified  timestamptz
		) ON COMMIT DROP;

		CREATE TEMP TABLE IF NOT EXISTS mal_comps_stage (
			id                   text,
			malicious_package_id text,
			purl                 text,
			ecosystem            text,
			version              text,
			semver_introduced    text,
			semver_fixed         text,
			version_introduced   text,
			version_fixed        text
		) ON COMMIT DROP;`)
	if err != nil {
		return fmt.Errorf("could not create staging tables: %w", err)
	}
	return nil
}

func clearStagingTables(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		TRUNCATE TABLE cves_stage;
		TRUNCATE TABLE cve_relationships_stage;
		TRUNCATE TABLE affected_components_stage;
		TRUNCATE TABLE cve_affected_component_stage;
		TRUNCATE TABLE exploits_stage;
		TRUNCATE TABLE mal_pkgs_stage;
		TRUNCATE TABLE mal_comps_stage;
		TRUNCATE TABLE epss_stage;
		TRUNCATE TABLE kev_stage;
		`)
	if err != nil {
		return fmt.Errorf("could not clear staging tables: %w", err)
	}
	return nil
}

// if we insert a lot of entries its faster to drop indexes and constrains and then rebuilding them afterwards instead of maintaining them on each insert
// also set some session parameters optimized for bulk inserts
func PrepareBulkInsert(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
	SET LOCAL synchronous_commit = OFF; -- this makes postgresql return as soon as the WAL has been written to and we do not need to wait until the contents have been written to the disk

	-- first drop all foreign key constraints between the tables since they depend on the primary keys
	ALTER TABLE public.cve_relationships DROP CONSTRAINT IF EXISTS fk_cve_relationships_source;

	ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_affected_component;
	ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;
	
	-- need to be dropped before dropping cves_cve_unique constraint
	ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve; 
	ALTER TABLE public.exploits DROP CONSTRAINT IF EXISTS fk_cves_exploits;
	ALTER TABLE public.weaknesses DROP CONSTRAINT IF EXISTS fk_cves_weaknesses;
	ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS fk_vex_rules_cve;

	-- then drop all primary key (and unique) constraints
	-- do not drop cves_pkey since we still need that index to detect and resolve duplicates
	-- do not drop cve_relationships_pkey since we need that index to detect ON CONFLICT
	-- affected_components_pkey and cve_affected_component_pkey are dropped here for bulk load
	-- performance; they are re-added by AddIndexesAndConstraints after all rows are inserted
	ALTER TABLE public.cves DROP CONSTRAINT IF EXISTS cves_cve_unique;
	ALTER TABLE affected_components DROP CONSTRAINT IF EXISTS affected_components_pkey;
	ALTER TABLE cve_affected_component DROP CONSTRAINT IF EXISTS cve_affected_component_pkey;
	
	-- lastly drop all indexes (might be redundant but safe)
	DROP INDEX IF EXISTS idx_affected_components_semver_fixed;
    DROP INDEX IF EXISTS idx_affected_components_semver_introduced;
    DROP INDEX IF EXISTS idx_affected_components_version_fixed;
    DROP INDEX IF EXISTS idx_affected_components_version_introduced;
    DROP INDEX IF EXISTS idx_affected_components_p_url;
    DROP INDEX IF EXISTS idx_affected_components_purl_without_version;
    DROP INDEX IF EXISTS idx_affected_components_version;

	DROP INDEX IF EXISTS idx_affected_component_purl_version;

	DROP INDEX IF EXISTS idx_affected_component_purl_semver_range;

	DROP INDEX IF EXISTS cve_affected_component_affected_component_id;
	DROP INDEX IF EXISTS cve_affected_component_cve_id;
	DROP INDEX IF EXISTS idx_cve_affected_component_cve_id_aff_comp_id;

	DROP INDEX IF EXISTS idx_cve_relationships_target_cve;`)
	if err != nil {
		return fmt.Errorf("could not drop indexes and constraints on tables: %w", err)
	}
	return nil
}

func AddIndexesAndConstraints(ctx context.Context, tx pgx.Tx) error {
	slog.Info("start building indexes and re-adding constraints")
	totalStart := time.Now()
	_, err := tx.Exec(ctx, `
	SET LOCAL maintenance_work_mem = '4GB';
	SET LOCAL max_parallel_maintenance_workers = 8;
	SET LOCAL max_parallel_workers = 16;
	SET LOCAL max_parallel_workers_per_gather = 8;

	ALTER TABLE affected_components ADD CONSTRAINT affected_components_pkey PRIMARY KEY (id);
	ALTER TABLE cve_affected_component ADD CONSTRAINT cve_affected_component_pkey PRIMARY KEY (affected_component_id, cve_id);
	`)
	if err != nil {
		return fmt.Errorf("could not apply primary key constraints: %w", err)
	}
	slog.Info("finished adding primary key constraints", "took", time.Since(totalStart))

	start := time.Now()
	_, err = tx.Exec(ctx, `
	-- Then add the foreign key constraints
	ALTER TABLE public.cves ADD CONSTRAINT cves_cve_unique UNIQUE (cve);
	ALTER TABLE public.cve_relationships ADD CONSTRAINT fk_cve_relationships_source FOREIGN KEY (source_cve) REFERENCES public.cves (cve) ON DELETE CASCADE;

	ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_affected_component FOREIGN KEY (affected_component_id) REFERENCES public.affected_components (id) ON DELETE CASCADE;
	ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_cve FOREIGN KEY (cve_id) REFERENCES public.cves (id) ON DELETE CASCADE;

	ALTER TABLE public.exploits ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;`)
	if err != nil {
		return fmt.Errorf("could not apply foreign key constraints: %w", err)
	}
	slog.Info("finished applying all foreign key constraints", "took", time.Since(start))

	start = time.Now()
	_, err = tx.Exec(ctx, `
	-- Lastly rebuild the indexes
    CREATE INDEX IF NOT EXISTS cve_affected_component_cve_id ON public.cve_affected_component USING hash (cve_id);

	CREATE INDEX idx_cve_relationships_target_cve ON public.cve_relationships USING btree (target_cve);
	
	CREATE INDEX idx_affected_component_purl_version
  		ON affected_components (purl, version);

	CREATE INDEX idx_affected_component_purl_semver_range
  		ON affected_components (purl, semver_introduced, semver_fixed)
 		WHERE semver_introduced IS NOT NULL OR semver_fixed IS NOT NULL;`)
	if err != nil {
		return fmt.Errorf("could not build indexes: %w", err)
	}
	slog.Info("finished building all indexes", "took", time.Since(start))

	// at last run analyze on all vuln tables to help the planner choose better execution plans in the future
	start = time.Now()
	_, err = tx.Exec(ctx, `
	ANALYZE cves;
	ANALYZE affected_components;
	ANALYZE cve_relationships;
	ANALYZE cve_affected_component;`)
	if err != nil {
		return fmt.Errorf("could not analyze tables: %w", err)
	}
	slog.Info("finished analyzing all updated tables", "took", time.Since(start))
	slog.Info("finished adding constraints and building indexes", "took", time.Since(totalStart))
	return nil
}

// after importing check if the database state is consistent
// runScopedCleanUpJobs removes orphaned affected_components and CVEs that resulted
// from deleting the given pivot rows. Only checks the specific IDs involved rather
// than scanning the full tables.
func runCleanUpJobs(ctx context.Context, tx pgx.Tx) {
	slog.Info("start running sanity checks")
	// first delete all cves which have no affected components and also none of their relationships does
	start := time.Now()
	_, err := tx.Exec(ctx, `
	DELETE FROM cves 
	WHERE id IN (
	SELECT 
		cves.id
	FROM 
		cves
	LEFT JOIN 
		cve_affected_component cac ON cac.cve_id = cves.id
	LEFT JOIN (
    	cve_relationships cr
    	JOIN cves temp_cves ON temp_cves.cve = cr.target_cve
    	JOIN cve_affected_component temp_cac ON temp_cac.cve_id = temp_cves.id
	) ON cr.source_cve = cves.cve
	WHERE 
		cac.cve_id IS NULL 		
  	AND 
		cr.source_cve IS NULL 
	);`)
	if err != nil {
		slog.Error("could not clean up orphan cves, continuing...", "error", err)
	} else {
		slog.Info("successfully cleaned up orphan cves", "took", time.Since(start))
	}

	start = time.Now()
	_, err = tx.Exec(ctx, `
	DELETE FROM 
		affected_components
	WHERE NOT EXISTS 
		(
			SELECT FROM cve_affected_component 
			WHERE affected_component_id = id
		)
	;`)
	if err != nil {
		slog.Error("could not clean up orphan affected components, continuing...", "error", err)
	} else {
		slog.Info("successfully cleaned up orphan affected components", "took", time.Since(start))
	}
}

func shouldIgnoreVulnerabilityID(id string) bool {
	prefix, _, ok := strings.Cut(id, "-")
	if !ok {
		// false negatives are ok
		return false
	}

	return slices.Contains(ignoreVulnerabilityEcosystems, prefix)
}
