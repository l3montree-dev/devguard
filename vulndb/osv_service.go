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
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

type osvService struct {
	httpClient                *http.Client
	affectedCmpRepository     shared.AffectedComponentRepository
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	configService             shared.ConfigService
	pool                      *pgxpool.Pool
}

func NewOSVService(affectedCmpRepository shared.AffectedComponentRepository, cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository, configService shared.ConfigService, pool *pgxpool.Pool) osvService {
	// use custom transport to adjust the workload to the number of go routines
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   90 * time.Second,
			KeepAlive: 90 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          numberOfSingleFetchers * 2,
		MaxIdleConnsPerHost:   numberOfSingleFetchers,
		MaxConnsPerHost:       numberOfSingleFetchers,
		IdleConnTimeout:       45 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	transport := otelhttp.NewTransport(utils.EgressRoundTripper{R: base})

	return osvService{
		httpClient:                &http.Client{Transport: transport, Timeout: 90 * time.Second},
		affectedCmpRepository:     affectedCmpRepository,
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		configService:             configService,
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

type OSVWithEcosystem struct {
	OSV       *dtos.OSV
	Ecosystem string
}

const numberOfSingleFetchers = 100
const numberOfZipWorkers = 10

const debugLocalZips = true

var deduplicateCveMap = sync.Map{} // map[string]struct{} to track already processed CVE IDs and avoid duplicates
type zipJob struct {
	File      *zip.File
	Ecosystem string
}

func (integrity tableIntegrityInformation) isEqual(compareInformation tableIntegrityInformation) bool {
	return integrity.TotalCount == compareInformation.TotalCount && bytes.Equal(integrity.Checksum, compareInformation.Checksum)
}

// imports the newest vulnerability data from the OCI registry (gob file) and applies it to our vulndb tables
func (s osvService) ImportRC(ctx context.Context) error {
	slog.Info("start vulndb import")
	start := time.Now()

	workingDir, err := pullVulnDBFromPackageRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not pull from remote repository: %w", err)
	}
	defer os.RemoveAll(workingDir)

	gobFile, err := os.Open(workingDir + "/allOSVVulns.gob.zst")
	if err != nil {
		return fmt.Errorf("could not open vulndb gob file: %w", err)
	}
	defer gobFile.Close()

	zstWriter, err := zstd.NewReader(gobFile)
	if err != nil {
		return fmt.Errorf("could not create zstd reader: %w", err)
	}
	defer zstWriter.Close()

	osvVulns := make([]OSVWithTimestamp, 0, 1<<18)
	if err := gob.NewDecoder(zstWriter).Decode(&osvVulns); err != nil {
		return fmt.Errorf("could not decode vulndb gob file: %w", err)
	}
	slog.Info("decoded gob file", "amount", len(osvVulns))

	var lastUpdate string

	if err := s.configService.GetJSONConfig(ctx, "vulndb.lastRCImport", &lastUpdate); err == nil {
		slog.Info("found last import timestamp, only loading diff since last import")
		lastUpdateTimestamp, err := time.Parse(time.RFC3339Nano, lastUpdate)
		if err != nil {
			return fmt.Errorf("could not parse config timestamp: %w", err)
		}
		filteredVulns := make([]OSVWithTimestamp, 0, 10_000)

		// filter only the vulns since the last import
		for _, vuln := range osvVulns {
			modifiedTimestamp := vuln.ModifiedTimestamp
			if modifiedTimestamp.After(lastUpdateTimestamp) {
				filteredVulns = append(filteredVulns, vuln)
			} else {
				continue
			}
		}
		osvVulns = filteredVulns

	} else {
		slog.Info("could not determine last import, loading full database")
	}

	if len(osvVulns) == 0 {
		slog.Info("vulnerability database is already up to date")
		return nil
	}
	rows, err := buildVulnDBRows(ctx, s.affectedCmpRepository, osvVulns)
	if err != nil {
		return fmt.Errorf("could not build rows from osv objects: %w", err)
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could acquire postgresql connection: %w", err)
	}
	defer conn.Release()

	if err := s.writeToDatabase(ctx, conn, rows, false); err != nil {
		return fmt.Errorf("could not process new OSV data, error: %w", err)
	}

	integrityInformation, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("could not calculate integrity information; %w", err)
	}
	valid, databaseStateTime, err := validateIntegrityInformation(workingDir, integrityInformation)
	if err != nil {
		return fmt.Errorf("could not validate information: %w", err)
	}
	if !valid {
		return fmt.Errorf("validation was not successful!")
	}
	slog.Info("successfully validated checksums")

	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", databaseStateTime.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	slog.Info("finished vulndb import", "time", time.Since(start))
	return nil
}

func validateIntegrityInformation(workingDir string, localIntegrityInformation []tableIntegrityInformation) (bool, time.Time, error) {
	fd, err := os.Open(workingDir + "/integrity_checks.json")
	if err != nil {
		return false, time.Time{}, fmt.Errorf("could not open integrity check json file: %w", err)
	}

	var groundTruth integrityInformation
	err = json.NewDecoder(fd).Decode(&groundTruth)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("could not decode remote integrity information")
	}

	for _, tableIntegrity := range localIntegrityInformation {
		found := false
		for _, tableGroundTruth := range groundTruth.TableIntegrity {
			if tableGroundTruth.TableName == tableIntegrity.TableName {
				if !tableIntegrity.isEqual(tableGroundTruth) {
					slog.Error("invalid checksum when importing", "table", tableIntegrity.TableName)
					return false, time.Time{}, nil
				} else {
					found = true
					break
				}
			}
		}
		if !found {
			return false, time.Time{}, fmt.Errorf("could not find integrity information for table %s", tableIntegrity.TableName)
		}
	}
	return true, groundTruth.ImportTimestamp, nil
}

func writeGobFile(object any, fileName string) error {
	gobFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("could not create gob file: %w", err)
	}
	defer gobFile.Close()
	// create a zstd encoder
	zstdWriter, err := zstd.NewWriter(gobFile, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return fmt.Errorf("could not create zstd writer: %w", err)
	}
	defer zstdWriter.Close()
	if err := gob.NewEncoder(zstdWriter).Encode(object); err != nil {
		return fmt.Errorf("could not encode object to gob file: %w", err)
	}
	return nil
}

type OSVWithTimestamp struct {
	OSV               *dtos.OSV `json:"osv"`
	ModifiedTimestamp time.Time `json:"modified"`
}

func (s osvService) ExportRC(ctx context.Context) error {
	slog.Info("start vulndb export")

	importStart := time.Now() //10:57 bonn

	zipPushWaitGroup := &sync.WaitGroup{}
	zipWorkWaitGroup := &sync.WaitGroup{}

	var fetchFailures atomic.Int64

	zipJobs := make(chan zipJob, 10_000)
	vulnData := make(chan *dtos.OSV, 5000)

	fetchingStart := time.Now()

	for range numberOfZipWorkers {
		zipWorkWaitGroup.Add(1)
		go s.zipWorkerFunction(zipWorkWaitGroup, zipJobs, vulnData, importStart, &fetchFailures)
	}

	zipPushWaitGroup.Add(1)
	go s.fetchingController(zipPushWaitGroup, zipJobs, &fetchFailures)

	// handle sync via independent go routines
	go func() {
		zipPushWaitGroup.Wait()
		close(zipJobs)
	}()

	go func() {
		zipWorkWaitGroup.Wait()
		close(vulnData)
	}()

	// collect all OSV objects first
	allOSVVulns := make([]OSVWithTimestamp, 0, 200_000)
	for osvObject := range vulnData {
		allOSVVulns = append(allOSVVulns, OSVWithTimestamp{OSV: osvObject, ModifiedTimestamp: osvObject.Modified})
	}

	// abort before any DB work if any fetch failed — watermark stays where it is, next run retries the whole window
	if n := fetchFailures.Load(); n > 0 {
		return fmt.Errorf("aborting import: %d ids could not be fetched; watermark not advanced, will retry on next run", n)
	}

	if len(allOSVVulns) == 0 {
		slog.Warn("could not fetch any OSV vulns")
		return nil
	}

	sortStart := time.Now()
	slices.SortFunc(allOSVVulns, func(v1, v2 OSVWithTimestamp) int {
		return -v1.ModifiedTimestamp.Compare(v2.ModifiedTimestamp)
	})
	slog.Info("finished sorting slice", "amount", len(allOSVVulns), "time", time.Since(sortStart), "latest entry", allOSVVulns[0].ModifiedTimestamp.Format(time.DateTime))

	// save all vulns for a fresh import
	if err := writeGobFile(allOSVVulns, "allOSVVulns.gob.zst"); err != nil {
		return err
	}
	slog.Info("finished collecting results start processing osv data", "fetching time", time.Since(fetchingStart))

	// build all the rows from the OSV objects
	rows, err := buildVulnDBRows(ctx, s.affectedCmpRepository, allOSVVulns)
	if err != nil {
		return fmt.Errorf("could not build vulndb rows: %w", err)
	}

	// acquire a connection first
	// use pgx for support of the COPY function
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could acquire postgresql connection: %w", err)
	}
	defer conn.Release()

	err = s.writeToDatabase(ctx, conn, rows, false)
	if err != nil {
		return fmt.Errorf("could not process new OSV data, error: %w", err)
	}

	// the core job is done; run sanity checks/clean ups afterwards
	//runCleanUpJobs(ctx, conn.Conn())

	tableIntegrity, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("could not calculate the integrity information for tables: %w", err)
	}

	slices.SortFunc(tableIntegrity, func(a, b tableIntegrityInformation) int {
		return strings.Compare(a.TableName, b.TableName)
	})

	integrityFD, err := os.Create("integrity_checks.json")
	if err != nil {
		return fmt.Errorf("could not create integrity_checks.json: %w", err)
	}
	defer integrityFD.Close()

	jsonContents, err := json.Marshal(integrityInformation{TableIntegrity: tableIntegrity, ImportTimestamp: importStart})
	if err != nil {
		return fmt.Errorf("could not parse integrity information to json format: %w", err)
	}

	if _, err := integrityFD.Write(jsonContents); err != nil {
		return fmt.Errorf("could not write json to file: %w", err)
	}

	slog.Info("finished vulndb export", "time", time.Since(importStart))
	return nil
}

// vulnDBArtifactFiles enumerates the per-file blobs that the workflow pushes
// to the OCI registry. Each file is cosign-signed independently and must
// pass verification before the importer is allowed to read it.
var vulnDBArtifactFiles = []string{
	"allOSVVulns.gob.zst",
	"integrity_checks.json",
}

const vulnDBPubKeyFile = "cosign.pub"

func pullVulnDBFromPackageRegistry(ctx context.Context) (string, error) {
	reg := "ghcr.io/l3montree-dev/devguard/vulndb/osv-mirror"
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return "", fmt.Errorf("could not connect to remote repository: %w", err)
	}

	outpath, err := os.MkdirTemp("", "vulndb")
	if err != nil {
		return "", fmt.Errorf("could not create temp directory: %w", err)
	}

	fs, err := file.New(outpath)
	if err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not create file store: %w", err)
	}

	// pull the multi-file artifact (modified_id.csv, ecosystem.zip, integrity_checks.json)
	const tag = "latest"
	if _, err = oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not copy artifact from remote repository: %w", err)
	}

	// pull the matching signatures (one .sig per file) from the sibling tag
	const sigTag = tag + ".sig"
	if _, err = oras.Copy(ctx, repo, sigTag, fs, sigTag, oras.DefaultCopyOptions); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not copy signatures from remote repository: %w", err)
	}

	// verify each blob against its signature before any caller is allowed
	// to use the working dir. If any signature fails we wipe the dir so a
	// partial/untrusted state cannot leak into the import path.
	for _, name := range vulnDBArtifactFiles {
		blob := outpath + "/" + name
		sig := blob + ".sig"
		if err := verifySignature(ctx, vulnDBPubKeyFile, sig, blob); err != nil {
			os.RemoveAll(outpath)
			return "", fmt.Errorf("could not verify signature for %s: %w", name, err)
		}
	}
	slog.Info("successfully verified signatures for all vulndb files")
	return outpath, nil
}

type tableIntegrityInformation struct {
	TableName  string `json:"table_name"`
	Checksum   []byte `json:"checksum"`
	TotalCount int    `json:"total_count"`
}

// computes and returns the tables integrity information using the provided query
func calculateIntegrityInformationForTable(ctx context.Context, pool *pgxpool.Pool, table string, query string) (tableIntegrityInformation, error) {
	var result tableIntegrityInformation
	result.TableName = table

	start := time.Now()
	slog.Info("start calculating integrity information", "table", table)

	err := pool.QueryRow(ctx, query).Scan(&result.TotalCount, &result.Checksum)
	if err != nil {
		return result, fmt.Errorf("could not calculate integrity information for table %s: %w", table, err)
	}

	slog.Info("finished calculating integrity information", "table", table, "time", time.Since(start))

	return result, nil
}

type integrityInformation struct {
	TableIntegrity  []tableIntegrityInformation `json:"table_integrity"`
	ImportTimestamp time.Time                   `json:"import_timestamp"`
}

func calculateTotalIntegrityInformation(ctx context.Context, pool *pgxpool.Pool) ([]tableIntegrityInformation, error) {

	queries := map[string]string{
		"cves": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id::text, '\0') || '|' ||
					coalesce(description, '\0') || '|' ||
					coalesce(cvss::text, '\0') || '|' ||
					coalesce(vector, '\0')
				) AS row_hash
				FROM cves
			) sub;`,

		"cve_relationships": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY source_cve, target_cve, relationship_type)) AS checksum
			FROM (
				SELECT source_cve, target_cve, relationship_type, md5(
					source_cve || '|' || target_cve || '|' || relationship_type
				) AS row_hash
				FROM cve_relationships
			) sub;`,

		"cve_affected_component": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY cve_id, affected_component_id)) AS checksum
			FROM (
				SELECT cve_id, affected_component_id, md5(
					cve_id::text || '|' || affected_component_id::text
				) AS row_hash
				FROM cve_affected_component
			) sub;`,

		"affected_components": `
			SELECT count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM affected_components;`,
	}

	mutex := &sync.Mutex{}
	waitGroup := &sync.WaitGroup{}

	results := make([]tableIntegrityInformation, 0, 4)
	errors := make([]error, 0, 4)

	// launch 1 go routine per table for parallelization of the calculations
	for table, query := range queries {
		waitGroup.Add(1)
		go func(table, query string) {
			defer waitGroup.Done()

			result, err := calculateIntegrityInformationForTable(ctx, pool, table, query)

			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				errors = append(errors, err)
			} else {
				results = append(results, result)
			}
		}(table, query)
	}

	waitGroup.Wait()

	if len(errors) > 0 {
		return results, fmt.Errorf("ran into one or multiple errors whilst trying to calculate integrity information: %v", errors)
	}

	return results, nil
}

// controls in what order and what method to use for each ecosystem
func (s osvService) fetchingController(zipPushWaitGroup *sync.WaitGroup, zipJobs chan zipJob, fetchFailures *atomic.Int64) {
	defer zipPushWaitGroup.Done()
	for _, ecosystem := range importEcosystems {

		// when fetching too many entries in an ecosystem, switch to downloading the full zip and filtering instead
		slog.Info("start fetching via zip", "ecosystem", ecosystem)
		zipPushWaitGroup.Add(1)
		go s.fetchEcosystemEntriesViaZip(zipPushWaitGroup, ecosystem, zipJobs, fetchFailures)
	}
	slog.Info("finished pushing all jobs")
}

func (s osvService) fetchEcosystemEntriesViaZip(zipPushWaitGroup *sync.WaitGroup, ecosystem string, zipJobs chan zipJob, fetchFailures *atomic.Int64) {
	defer zipPushWaitGroup.Done()
	start := time.Now()

	zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
	if err != nil {
		// whole ecosystem worth of ids lost; count each so the abort log reflects the real blast radius
		fetchFailures.Add(1)
		return
	}
	if len(zipReader.File) == 0 {
		fetchFailures.Add(1)
		return
	}

	for i := range zipReader.File {
		zipJobs <- zipJob{File: zipReader.File[i], Ecosystem: ecosystem}
	}
	slog.Info("finished pushing zip files", "ecosystem", ecosystem, "time elapsed", time.Since(start))
}

func (s osvService) getOSVZipContainingEcosystem(ecosystem string) (*zip.Reader, error) {
	if debugLocalZips {
		// check if file does already exist
		f, err := os.Open(fmt.Sprintf("%s.zip", ecosystem))
		if err == nil {
			// we already have that file on disk
			stat, err := f.Stat()
			if err != nil {
				return nil, errors.Wrap(err, "could not get file stats for local zip file")
			}
			return zip.NewReader(f, stat.Size())
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

	if debugLocalZips {
		// save the file on disk
		outFile, err := os.Create(fmt.Sprintf("%s.zip", ecosystem))
		if err != nil {
			return nil, errors.Wrap(err, "could not create file for local zip")
		}
		// create a TEE Reader do read the body twice
		tee := io.TeeReader(res.Body, outFile)
		// set the response body to the TEE reader so it can be read by the zip reader and saved to disk at the same time
		res.Body = io.NopCloser(tee)
	}

	return utils.ZipReaderFromResponse(res)
}

func (s osvService) zipWorkerFunction(zipWorkWaitGroup *sync.WaitGroup, zipJobs chan zipJob, output chan *dtos.OSV, importStart time.Time, fetchFailures *atomic.Int64) {
	defer zipWorkWaitGroup.Done()
	for zipJob := range zipJobs {
		if _, loaded := deduplicateCveMap.LoadOrStore(zipJob.File.Name, struct{}{}); loaded {
			continue
		}
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

		if shouldIgnoreVulnerabilityID(osvEntry.ID) {
			continue
		}

		if osvEntry.Modified.After(importStart) {
			slog.Warn("ran into race condition on import, skipping vuln with newer information")
			continue
		}
		output <- &osvEntry
	}
}

// build all the vuln database rows from the OSV objects
func buildVulnDBRows(ctx context.Context, affectedCmpRepository shared.AffectedComponentRepository, allEntries []OSVWithTimestamp) (vulndbRows, error) {
	// get the current state of the affected components to avoid creating duplicate entries
	currentCVEAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*5)
	err := affectedCmpRepository.GetDB(ctx, nil).Raw(`SELECT * FROM cve_affected_component;`).Find(&currentCVEAffectedComponents).Error
	if err != nil {
		return vulndbRows{}, fmt.Errorf("could not get current state of affected components: %w", err)
	}

	// build a map of the current state for faster lookups of the existing state
	// used for deduplicating rows in memory rather than on insert
	isAffectedComponentPresent := make(map[int64]struct{}, len(currentCVEAffectedComponents))
	isCVEAffectedComponentPresent := make(map[cveAffectedComponentRow]struct{}, len(currentCVEAffectedComponents)*7)
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

		// only then process the rest
		cveRelationships = append(cveRelationships, relationships...)

		// create the cve first
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
	slog.Info("finished building rows", "building time", time.Since(buildingTime))
	return vulndbRows{CVEs: cves, CVERelationships: cveRelationships, AffectedComponents: affectedComponents, CVEAffectedComponents: cveAffectedComponents}, nil
}

// write all rows to the database using the appropriate insert method
func (s osvService) writeToDatabase(ctx context.Context, conn *pgxpool.Conn, rows vulndbRows, createTemp bool) error {
	slog.Info("start writing rows to database")
	start := time.Now()

	// start the transaction; handle everything inside this single one to guarantee atomicity of the import
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not start transaction: %w", err)
	}
	defer func() {
		err := tx.Rollback(ctx)
		if err != nil && err != pgx.ErrTxClosed { // only log if the error is not from trying to roll back a closed transaction
			slog.Error("could not roll back transaction successfully, database state is potentially inconsistent!")
			panic(err)
		}
	}() // if we run into any errors rollback the entire transaction

	const bulkThreshold = 200_000

	reachedBulkThreshold := len(rows.AffectedComponents) > bulkThreshold || len(rows.CVEAffectedComponents) > bulkThreshold
	// if we reach a certain threshold of data we switch to an optimized bulk insert method:
	if reachedBulkThreshold {
		// index updates and constraint checks on each insert slow the process down drastically
		// drop all first and later re-apply all again
		slog.Info("reached bulk insert threshold; using bulk optimized import strategy")
		err = PrepareBulkInsert(ctx, tx)
		if err != nil {
			return fmt.Errorf("could not prepare transaction: %w", err)
		}
	}

	// then we can just stream all our data with the COPY clause straight into the tables
	err = insertCVEsBulk(ctx, tx, rows.CVEs, createTemp)
	if err != nil {
		return fmt.Errorf("could not insert cves: %w", err)
	}

	err = insertCVERelationshipsBulk(ctx, tx, rows.CVERelationships, createTemp)
	if err != nil {
		return fmt.Errorf("could not insert cve relationships: %w", err)
	}

	err = insertAffectedComponentsBulk(ctx, tx, rows.AffectedComponents, createTemp)
	if err != nil {
		return fmt.Errorf("could not insert affected_components: %w", err)
	}
	if err := insertCVEAffectedComponentsBulk(ctx, tx, rows.CVEAffectedComponents, createTemp); err != nil {
		return fmt.Errorf("could not insert cve_affected_component: %w", err)
	}

	if reachedBulkThreshold {
		// after we finish inserting the data we need to re-apply all previously deleted constraints and indexes
		err = AddIndexesAndConstraints(ctx, tx)
		if err != nil {
			return fmt.Errorf("could not re-add constraints and indexes on table: %w", err)
		}
	}

	// finally commit the whole import transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}
	slog.Info("finished writing everything to the database", "time", time.Since(start))
	return nil
}

// insert cves using copy to stream data into a staging table and then merging the staging table with the cves table
// this lets us handle on conflicts and updates gracefully, while still having the speed of copy
func insertCVEsBulk(ctx context.Context, tx pgx.Tx, cves []models.CVE, createTemp bool) error {
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
	if !createTemp {
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
	} else {
		if _, err := tx.Exec(ctx, `
		CREATE TABLE cves_temp (LIKE cves INCLUDING ALL);`); err != nil {
			return fmt.Errorf("could not create temp table 1: %w", err)
		}

		if _, err := tx.Exec(ctx, `
		INSERT INTO cves_temp (id, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector)
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
	}
	slog.Info("finished inserting into cves", "time", time.Since(start))
	return nil
}

// insert into cve relationships using copy in combination with a staging table
// the staging table step is used to able to handle on conflict, effectively resulting in the deduplication of rows before applying the primary key
func insertCVERelationshipsBulk(ctx context.Context, tx pgx.Tx, cveRelationships []models.CVERelationship, createTemp bool) error {
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

	if !createTemp {
		// then merge both tables and ignore duplicate rows
		if _, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
		SELECT target_cve, source_cve, relationship_type
		FROM cve_relationships_stage
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`); err != nil {
			return fmt.Errorf("could not insert from staging into cve_relationships: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
		CREATE TABLE cve_relationships_temp (LIKE cve_relationships INCLUDING ALL);`); err != nil {
			return fmt.Errorf("could not create temp table 2: %w", err)
		}

		// then merge both tables and ignore duplicate rows
		if _, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships_temp (target_cve, source_cve, relationship_type)
		SELECT target_cve, source_cve, relationship_type
		FROM cve_relationships_stage
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`); err != nil {
			return fmt.Errorf("could not insert from staging into cve_relationships: %w", err)
		}
	}

	slog.Info("finished inserting into cve_relationships", "time", time.Since(start))
	return nil
}

// inserts into affected components using copy + staging table approach
// the staging table is needed in this case to be able to transform semver values to the semver datatype since COPY lacks this functionality
func insertAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, components []models.AffectedComponent, createTemp bool) error {
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

	if !createTemp {
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
	} else {
		if _, err := tx.Exec(ctx, `
		CREATE TABLE affected_components_temp (LIKE affected_components INCLUDING ALL);`); err != nil {
			return fmt.Errorf("could not create temp table 3: %w", err)
		}
		// finally merge both tables and cast the semver texts from the staging table to the semver datatype in the real table
		// no ON CONFLICT needed since we deduplicated in memory
		if _, err := tx.Exec(ctx, `
		INSERT INTO affected_components_temp (
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
	}
	slog.Info("finished inserting into affected_components", "time", time.Since(start))
	return nil
}

// insert into the cve affected components pivot table using COPY
func insertCVEAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, pivotRows []cveAffectedComponentRow, createTemp bool) error {
	slog.Info("inserting into cve_affected_component using bulk insert", "amount", len(pivotRows))
	start := time.Now()

	// stream data straight into the table using COPY (by pass query executioner)
	// no ON CONFLICT needed since we deduplicated in memory
	columnNames := []string{"affected_component_id", "cve_id"}
	if !createTemp {
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_affected_component"}, columnNames, pgx.CopyFromSlice(len(pivotRows), func(i int) ([]any, error) {
			row := pivotRows[i]
			return []any{row.AffectedComponentID, row.CveID}, nil
		}))
		if err != nil {
			return fmt.Errorf("could not copy cve affected component rows into table: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
		CREATE TABLE cve_affected_component_temp (LIKE cve_affected_component INCLUDING ALL);`); err != nil {
			return fmt.Errorf("could not create temp table 4: %w", err)
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_affected_component_temp"}, columnNames, pgx.CopyFromSlice(len(pivotRows), func(i int) ([]any, error) {
			row := pivotRows[i]
			return []any{row.AffectedComponentID, row.CveID}, nil
		}))
		if err != nil {
			return fmt.Errorf("could not copy cve affected component rows into table: %w", err)
		}
	}
	slog.Info("finished inserting into cve_affected_component", "time", time.Since(start))
	return nil
}

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
	-- do not drop cves_pkey since we still need that index to detect and resolve indexes
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
	
	ALTER TABLE public.dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE; 

	ALTER TABLE public.exploits ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;
	ALTER TABLE public.weaknesses ADD CONSTRAINT fk_cves_weaknesses FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
	ALTER TABLE public.vex_rules ADD CONSTRAINT fk_vex_rules_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;`)
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
	slog.Info("finsihed building all indexes", "time", time.Since(start))
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
func runCleanUpJobs(ctx context.Context, conn *pgx.Conn) {
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
		return true
	}
	return slices.Contains(ignoreVulnerabilityEcosystems, prefix)
}
