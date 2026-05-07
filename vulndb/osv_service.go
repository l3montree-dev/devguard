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
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
)

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
	"MAL",
	"CGA",
	"GSD",
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

// applyOSVEntries filters the provided entries by lastImportTime and writes them to the database
// using the provided pgx transaction. The caller is responsible for Begin/Commit/Rollback.
func (s osvService) applyOSVEntries(ctx context.Context, tx pgx.Tx, osvVulns []OSVEntry, lastImportTime time.Time) error {
	if !lastImportTime.IsZero() {
		slog.Info("found last import timestamp, only loading diff since last import")
		filtered := make([]OSVEntry, 0, 10_000)
		for _, vuln := range osvVulns {
			if vuln.ModifiedTimestamp.After(lastImportTime) {
				filtered = append(filtered, vuln)
			}
		}
		osvVulns = filtered
	} else {
		slog.Info("no last import timestamp, loading full database")
	}

	if len(osvVulns) == 0 {
		slog.Info("OSV vulnerability database is already up to date")
		return nil
	}

	rows, err := buildVulnDBRows(ctx, tx, osvVulns)
	if err != nil {
		return fmt.Errorf("could not build rows from osv objects: %w", err)
	}

	if err := s.writeToDatabase(ctx, tx, rows); err != nil {
		return fmt.Errorf("could not write OSV rows to database, error: %w", err)
	}
	return nil
}

// fetchAndImportOSV fetches all OSV vulnerabilities from the network, writes them to the
// database via tx, runs cleanup, and returns the surviving entries plus surviving CVE IDs.
// The caller is responsible for Begin/Commit/Rollback on tx.
func (s osvService) fetchAndImportOSV(ctx context.Context, tx pgx.Tx, importStart time.Time) ([]OSVEntry, map[string]struct{}, error) {
	zipPushWaitGroup := &sync.WaitGroup{}
	zipWorkWaitGroup := &sync.WaitGroup{}

	var fetchFailures atomic.Int64

	zipJobs := make(chan zipJob, 10_000)
	vulnData := make(chan *dtos.OSV, 5000)

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
	for osvObject := range vulnData {
		allOSVVulns = append(allOSVVulns, OSVEntry{OSV: osvObject, ModifiedTimestamp: osvObject.Modified})
	}

	// check if we ran into any errors while fetching
	if n := fetchFailures.Load(); n > 0 {
		return nil, nil, fmt.Errorf("aborting export: %d ids could not be fetched; will retry on next run", n)
	}

	// double check if we could fetch any data at all
	if len(allOSVVulns) == 0 {
		return nil, nil, fmt.Errorf("could not fetch any OSV vulns")
	}

	slog.Info("fetched OSV vulns", "amount", len(allOSVVulns), "latest", allOSVVulns[0].ModifiedTimestamp.Format(time.DateTime))

	// sort the slice so the import is able to fast exit after hitting the last timestamp
	slices.SortFunc(allOSVVulns, func(v1, v2 OSVEntry) int {
		return -v1.ModifiedTimestamp.Compare(v2.ModifiedTimestamp)
	})

	rows, err := buildVulnDBRows(ctx, tx, allOSVVulns)
	if err != nil {
		return nil, nil, fmt.Errorf("could not build vulndb rows: %w", err)
	}

	if err := s.writeToDatabase(ctx, tx, rows); err != nil {
		return nil, nil, fmt.Errorf("could not process new OSV data, error: %w", err)
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
	surviving := make(map[string]struct{}, len(rows.CVEs))
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
		if _, ok := surviving[e.OSV.ID]; ok {
			kept = append(kept, e)
		}
	}
	slog.Info("filtered OSV entries after cleanup", "before", len(allOSVVulns), "after", len(kept))
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
	slog.Info("finished pushing zip files", "ecosystem", ecosystem, "timeElapsed", time.Since(start))
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

func (s osvService) zipWorkerFunction(zipWorkWaitGroup *sync.WaitGroup, zipJobs chan zipJob, output chan *dtos.OSV, importStart time.Time, fetchFailures *atomic.Int64) {
	defer zipWorkWaitGroup.Done()
	for zipJob := range zipJobs {
		// only then open and decode the json into an osv object
		readCloser, err := zipJob.File.Open()
		if err != nil {
			fetchFailures.Add(1)
			slog.Error("could not open osv file", "file", zipJob.File.Name, "err", err)
			continue
		}

		osvEntry := dtos.OSV{}
		if err = json.NewDecoder(readCloser).Decode(&osvEntry); err != nil {
			readCloser.Close()
			fetchFailures.Add(1)
			slog.Error("could not parse osv file to OSV dto", "file", zipJob.File.Name, "err", err)
			continue
		}
		readCloser.Close()

		// double check if we want to ignore it based on the id value in the json
		if shouldIgnoreVulnerabilityID(osvEntry.ID) {
			continue
		}

		// cut all vulns which are newer than our import start
		if osvEntry.Modified.After(importStart) {
			slog.Warn("ran into race condition on import, skipping vuln with newer information")
			continue
		}
		output <- &osvEntry
	}
}

// build all the vuln database rows from the OSV objects
func buildVulnDBRows(ctx context.Context, tx pgx.Tx, allEntries []OSVEntry) (vulndbRows, error) {
	// get the current state of the affected components to avoid creating duplicate entries
	currentCVEAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*55)
	rows, err := tx.Query(ctx, `SELECT affected_component_id, cve_id FROM cve_affected_component`)
	if err != nil {
		return vulndbRows{}, fmt.Errorf("could not get current state of affected components: %w", err)
	}

	// convert the rows to a slice of cveAffectedComponentRow
	for rows.Next() {
		var row cveAffectedComponentRow
		if err := rows.Scan(&row.AffectedComponentID, &row.CveID); err != nil {
			rows.Close()
			return vulndbRows{}, fmt.Errorf("could not scan cve_affected_component row: %w", err)
		}
		currentCVEAffectedComponents = append(currentCVEAffectedComponents, row)
	}

	// build a map of the current state for faster lookups of the existing state
	// used for deduplicating rows in memory rather than on insert
	isAffectedComponentPresent := make(map[int64]struct{}, len(currentCVEAffectedComponents))
	isCVEAffectedComponentPresent := make(map[cveAffectedComponentRow]struct{}, len(currentCVEAffectedComponents))
	for _, cveAffectedComponent := range currentCVEAffectedComponents {
		isAffectedComponentPresent[cveAffectedComponent.AffectedComponentID] = struct{}{}
		isCVEAffectedComponentPresent[cveAffectedComponent] = struct{}{}
	}

	// allocate all slice for holding each entry
	cves := make([]models.CVE, 0, len(allEntries))
	cveRelationships := make([]models.CVERelationship, 0, len(allEntries)*2)
	affectedComponents := make([]models.AffectedComponent, 0, len(allEntries)*12) // use existing size relations for approximating the upper bound the slices size
	cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*55)

	slog.Info("start building rows", "amount", len(allEntries))
	buildingTime := time.Now()

	// then build the structs for each OSV object
	for i := range allEntries {
		// first calculate the components necessary for the skip condition
		relationships := transformer.OSVToCVERelationships(allEntries[i].OSV)

		affectedComponentsForCVE := transformer.AffectedComponentsFromOSV(allEntries[i].OSV)
		if len(affectedComponentsForCVE) == 0 && len(relationships) == 0 {
			continue // we do not need to process this entry since it will never be found
		}

		// only then continue building the remaining rows
		cveRelationships = append(cveRelationships, relationships...)

		// create the cve
		cve := transformer.OSVToCVE(allEntries[i].OSV)
		cve.ID = cve.CalculateHash()
		cves = append(cves, cve)

		// for each affected component check if its already present and create the respective pivot table entries
		for _, affectedComponent := range affectedComponentsForCVE {
			hash := affectedComponent.CalculateHashFast()

			affectedComponent.ID = hash // assign hash for later use
			row := cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: hash}

			if _, ok := isAffectedComponentPresent[hash]; !ok {
				affectedComponents = append(affectedComponents, affectedComponent)
				// add the new component, so that we do not have duplicates in the new data itself
				isAffectedComponentPresent[hash] = struct{}{}
			}

			if _, ok := isCVEAffectedComponentPresent[row]; !ok {
				cveAffectedComponents = append(cveAffectedComponents, row)
				// add the new cve-component, so that we do not have duplicates in the new data itself
				isCVEAffectedComponentPresent[row] = struct{}{}
			}
		}
	}
	slog.Info("finished building rows", "buildingTime", time.Since(buildingTime))
	return vulndbRows{CVEs: cves, CVERelationships: cveRelationships, AffectedComponents: affectedComponents, CVEAffectedComponents: cveAffectedComponents}, nil
}

// writeToDatabase writes all rows to the database inside the provided transaction.
// The caller is responsible for Begin/Commit/Rollback.
func (s osvService) writeToDatabase(ctx context.Context, tx pgx.Tx, rows vulndbRows) error {
	slog.Info("start writing rows to database")
	start := time.Now()

	const bulkThreshold = 200_000 // determine at what point to switch import strategy to bulk mode (dropping indexes and constraints before inserting)

	reachedBulkThreshold := len(rows.AffectedComponents) > bulkThreshold || len(rows.CVEAffectedComponents) > bulkThreshold
	if reachedBulkThreshold {
		slog.Info("reached bulk insert threshold; using bulk optimized import strategy")
		if err := PrepareBulkInsert(ctx, tx); err != nil {
			return fmt.Errorf("could not prepare transaction: %w", err)
		}
	}

	if err := insertCVEsBulk(ctx, tx, rows.CVEs); err != nil {
		return fmt.Errorf("could not insert cves: %w", err)
	}
	if err := insertCVERelationshipsBulk(ctx, tx, rows.CVERelationships); err != nil {
		return fmt.Errorf("could not insert cve relationships: %w", err)
	}
	if err := insertAffectedComponentsBulk(ctx, tx, rows.AffectedComponents); err != nil {
		return fmt.Errorf("could not insert affected_components: %w", err)
	}
	if err := insertCVEAffectedComponentsBulk(ctx, tx, rows.CVEAffectedComponents); err != nil {
		return fmt.Errorf("could not insert cve_affected_component: %w", err)
	}

	if reachedBulkThreshold {
		if err := AddIndexesAndConstraints(ctx, tx); err != nil {
			return fmt.Errorf("could not re-add constraints and indexes on table: %w", err)
		}
	}

	slog.Info("finished writing everything to the database", "time", time.Since(start))
	return nil
}

// insert cves using copy to stream data into a staging table and then merging the staging table with the cves table
// this lets us handle on conflicts and updates gracefully, while still having the speed of copy
func insertCVEsBulk(ctx context.Context, tx pgx.Tx, cves []models.CVE) error {
	if len(cves) == 0 {
		return nil
	}

	slog.Info("inserting into cves using staging table", "amount", len(cves))
	start := time.Now()

	// first create the staging table to load the data into
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE cves_stage (
			id                      bigint,
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
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create cves staging table: %w", err)
	}

	// copy data straight into the staging table
	columnNames := []string{"id", "cve", "date_published", "date_last_modified", "description", "cvss", "references", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile", "vector"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cves_stage"}, columnNames, pgx.CopyFromSlice(len(cves), func(i int) ([]any, error) {
		row := cves[i]
		return []any{row.ID, row.CVE, row.DatePublished, row.DateLastModified, row.Description, row.CVSS, row.References, row.CISAExploitAdd, row.CISAActionDue, row.CISARequiredAction, row.CISAVulnerabilityName, row.EPSS, row.Percentile, row.Vector}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve rows into staging table: %w", err)
	}

	// then insert from the staging table and update entries on conflicts (newest first)

	if _, err := tx.Exec(ctx, `
		INSERT INTO cves (id, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector)
		SELECT id, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector
		FROM cves_stage
		ON CONFLICT (id) DO UPDATE SET
			date_published     = EXCLUDED.date_published,
			date_last_modified = EXCLUDED.date_last_modified,
			description        = EXCLUDED.description,
			cvss               = EXCLUDED.cvss,
			vector             = EXCLUDED.vector`); err != nil {
		return fmt.Errorf("could not upsert from staging into cves: %w", err)
	}

	slog.Info("finished inserting into cves", "time", time.Since(start))
	return nil
}

// insert into cve relationships using copy in combination with a staging table
// the staging table step is used to able to handle on conflict, effectively resulting in the deduplication of rows before applying the primary key
func insertCVERelationshipsBulk(ctx context.Context, tx pgx.Tx, cveRelationships []models.CVERelationship) error {
	if len(cveRelationships) == 0 {
		return nil
	}
	slog.Info("inserting into cve_relationships using staging table", "amount", len(cveRelationships))
	start := time.Now()

	// first create staging table with no constraints
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE cve_relationships_stage (
			target_cve        text,
			source_cve        text,
			relationship_type text
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create cve_relationships staging table: %w", err)
	}

	// stream data straight into staging table
	columnNames := []string{"target_cve", "source_cve", "relationship_type"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_relationships_stage"}, columnNames, pgx.CopyFromSlice(len(cveRelationships), func(i int) ([]any, error) {
		row := cveRelationships[i]
		return []any{row.TargetCVE, row.SourceCVE, row.RelationshipType}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve relationship rows into staging table: %w", err)
	}

	// then merge both tables and ignore duplicate rows
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
		SELECT target_cve, source_cve, relationship_type
		FROM cve_relationships_stage
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`); err != nil {
		return fmt.Errorf("could not insert from staging into cve_relationships: %w", err)
	}

	slog.Info("finished inserting into cve_relationships", "time", time.Since(start))
	return nil
}

// inserts into affected components using copy + staging table approach
// the staging table is needed in this case to be able to transform semver values to the semver datatype since COPY lacks this functionality
func insertAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, components []models.AffectedComponent) error {
	slog.Info("inserting into affected_components using bulk insert", "amount", len(components))
	start := time.Now()

	// create staging table with COPY supported data types only (text instead of semver)
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE affected_components_stage (
			id                 bigint,
			
			purl               text,
			ecosystem          text,
			
			version            text,
			semver_introduced  text,
			semver_fixed       text,
			version_introduced text,
			version_fixed      text
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create staging table: %w", err)
	}

	// stream the values into the staging table; all affected components attributes are already default postgresql types
	columnNames := []string{"id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"affected_components_stage"}, columnNames, pgx.CopyFromSlice(len(components), func(i int) ([]any, error) {
		c := components[i]
		return []any{c.ID, c.PurlWithoutVersion, c.Ecosystem, c.Version, c.SemverIntroduced, c.SemverFixed, c.VersionIntroduced, c.VersionFixed}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy affected component rows into staging table: %w", err)
	}

	// finally merge both tables and cast the semver texts from the staging table to the semver datatype in the real table
	// no ON CONFLICT needed since we deduplicated in memory
	if _, err := tx.Exec(ctx, `
		INSERT INTO affected_components (
			id, purl, ecosystem,  version,
			semver_introduced, semver_fixed,
			version_introduced, version_fixed
		)
		SELECT
			id, purl, ecosystem, version,
			semver_introduced::semver, semver_fixed::semver,
			version_introduced, version_fixed
		FROM affected_components_stage`); err != nil {
		return fmt.Errorf("could not insert from staging into affected_components: %w", err)
	}

	slog.Info("finished inserting into affected_components", "time", time.Since(start))
	return nil
}

// insert into the cve affected components pivot table using COPY
func insertCVEAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, pivotRows []cveAffectedComponentRow) error {
	slog.Info("inserting into cve_affected_component using bulk insert", "amount", len(pivotRows))
	start := time.Now()

	// stream data straight into the table using COPY (bypass query executioner)
	// no ON CONFLICT needed since we deduplicated in memory
	columnNames := []string{"affected_component_id", "cve_id"}

	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_affected_component"}, columnNames, pgx.CopyFromSlice(len(pivotRows), func(i int) ([]any, error) {
		row := pivotRows[i]
		return []any{row.AffectedComponentID, row.CveID}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve affected component rows into table: %w", err)
	}

	slog.Info("finished inserting into cve_affected_component", "time", time.Since(start))
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
	-- Session tuning: all SET LOCAL — scoped to this transaction, preserves ACID.
	-- maintenance_work_mem dominates index-build time; raising it avoids on-disk sorts.
	-- max_parallel_maintenance_workers enables intra-index parallelism for btree builds.

	SET LOCAL maintenance_work_mem = '4GB';
	SET LOCAL max_parallel_maintenance_workers = 8;
	SET LOCAL max_parallel_workers = 16;
	SET LOCAL max_parallel_workers_per_gather = 8;
         
	-- First add the primary key constraints
	-- we did not drop the cves_pkey, so we do not need to add that
	ALTER TABLE affected_components ADD CONSTRAINT affected_components_pkey PRIMARY KEY (id);
	ALTER TABLE cve_affected_component ADD CONSTRAINT cve_affected_component_pkey PRIMARY KEY (affected_component_id,cve_id);
	`)
	if err != nil {
		return fmt.Errorf("could not apply primary key constraints: %w", err)
	}
	slog.Info("finished adding primary key constraints", "time", time.Since(totalStart))

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
	slog.Info("finished applying all foreign key constraints", "time", time.Since(start))

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
	slog.Info("finished building all indexes", "time", time.Since(start))

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
	slog.Info("finished analyzing all updated tables", "time", time.Since(start))
	slog.Info("finished adding constraints and building indexes", "time", time.Since(totalStart))
	return nil
}

// after importing check if the database state is consistent
func runCleanUpJobs(ctx context.Context, conn pgx.Tx) {
	slog.Info("start running sanity checks")
	// first delete all cves which have no affected components and also none of their relationships does
	start := time.Now()
	_, err := conn.Exec(ctx, `
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
		slog.Info("successfully cleaned up orphan cves", "time", time.Since(start))
	}

	start = time.Now()
	_, err = conn.Exec(ctx, `
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
		slog.Info("successfully cleaned up orphan affected components", "time", time.Since(start))
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
