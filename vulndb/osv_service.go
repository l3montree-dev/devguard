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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"gorm.io/gorm"
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
	return osvService{
		httpClient:                &http.Client{Transport: utils.EgressTransport},
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
	"Chainguard",
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

func (s osvService) getOSVZipContainingEcosystem(ecosystem string) (*zip.Reader, error) {
	req, err := http.NewRequest(http.MethodGet, osvBaseURL+"/"+ecosystem+"/all.zip", nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not download zip")
	}

	return utils.ZipReaderFromResponse(res)
}

func (s osvService) getEcosystems() ([]string, error) {
	// download the whole database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvBaseURL+"/ecosystems.txt", nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	res, err := s.httpClient.Do(req)
	defer res.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, "could not download ecosystems")
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not read body")
	}

	ecosystems := strings.Split(string(bodyBytes), "\n")

	// trim spaces for all entries
	for i, e := range ecosystems {
		ecosystems[i] = strings.TrimSpace(e)
	}

	// lastly filter out the ecosystems we are not using
	ecosystems = utils.Filter(ecosystems, func(ecosystem string) bool {
		return slices.Contains(importEcosystems, ecosystem)
	})

	return ecosystems, nil
}

const numOfGoRoutines int = 10

func (s osvService) Mirror(ctx context.Context) error {
	zips := make(chan *zip.Reader, 2)
	jobs := make(chan *zip.File, numOfGoRoutines*20)

	waitGroup := &sync.WaitGroup{}

	go s.workerZipFunction(ctx, zips)

	for range numOfGoRoutines {
		waitGroup.Add(1)
		go s.workerFileFunction(ctx, waitGroup, jobs)
	}

	// iterate over all files in the zip
	for zipReader := range zips {
		for _, file := range zipReader.File {
			jobs <- file
		}
	}
	close(jobs)
	waitGroup.Wait()

	return nil
}

func (s osvService) workerZipFunction(ctx context.Context, results chan<- *zip.Reader) {
	ecosystems, err := s.getEcosystems()
	if err != nil {
		slog.Error("could not get ecosystems", "err", err)
		return
	}
	for _, ecosystem := range ecosystems {
		if ecosystem == "" {
			continue
		}

		slog.Info("importing ecosystem", "ecosystem", ecosystem)
		start := time.Now()
		// remove all affected packages for this ecosystem
		err := s.affectedCmpRepository.DeleteAll(ctx, nil, ecosystem)
		if err != nil {
			slog.Error("could not delete affected packages", "err", err)
			continue
		}
		slog.Info("deleted all affected packages", "ecosystem", ecosystem, "duration", time.Since(start))

		// download the zip and extract it in memory
		zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
		if err != nil {
			slog.Error("could not read zip", "err", err)
			continue
		}
		if len(zipReader.File) == 0 {
			slog.Error("no files found in zip")
			continue
		}
		results <- zipReader
	}
	close(results)
}

func (s osvService) workerFileFunction(ctx context.Context, waitGroup *sync.WaitGroup, jobs <-chan *zip.File) {
	for job := range jobs {
		// read the file
		unzippedFileBytes, err := utils.ReadZipFile(job)
		if err != nil {
			slog.Error("could not read file", "err", err, "file", job.Name)
			continue
		}

		osv := dtos.OSV{}
		err = json.Unmarshal(unzippedFileBytes, &osv)
		if err != nil {
			slog.Error("could not unmarshal osv", "err", err)
			continue
		}

		// if we do not support the Vulnerability Ecosystem we do not want to handle it
		if shouldIgnoreVulnerabilityID(osv.ID) {
			continue
		}

		// first build the CVE based on the OSV and save it to the db
		tx := s.cveRepository.Begin(ctx)

		newCVE := transformer.OSVToCVE(&osv)

		err = s.cveRepository.CreateCVEWithConflictHandling(ctx, tx, &newCVE)
		if err != nil {
			slog.Error("could not save CVE", "CVE", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}

		relations := transformer.OSVToCVERelationships(&osv)

		err = s.cveRelationshipRepository.SaveBatch(ctx, tx, relations)
		if err != nil {
			slog.Error("could not save cve relation", "error", err)
			tx.Rollback()
			continue
		}

		affectedComponents := transformer.AffectedComponentsFromOSV(&osv, relations)

		// then create the affected components
		err = s.affectedCmpRepository.CreateAffectedComponentsUsingUnnest(ctx, tx, affectedComponents)
		if err != nil {
			slog.Error("could not save affected components", "cve", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}

		err = s.cveRepository.CreateCVEAffectedComponentsEntries(ctx, tx, &newCVE, affectedComponents)
		if err != nil {
			slog.Error("could not save to cve_affected_components relation table", "cve", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}
		tx.Commit()
	}
	waitGroup.Done()
}

func shouldIgnoreVulnerabilityID(id string) bool {
	prefix, _, ok := strings.Cut(id, "-")
	if !ok {
		// false negatives are ok
		return true
	}
	return slices.Contains(ignoreVulnerabilityEcosystems, prefix)
}

// sequential version of mirror for debugging purposes ONLY!
func (s osvService) MirrorNoConcurrency() error {
	ctx := context.Background()
	ecosystems, err := s.getEcosystems()
	if err != nil {
		slog.Error("could not get ecosystems", "err", err)
		return err
	}

	for _, ecosystem := range ecosystems {
		if ecosystem == "" {
			continue
		}

		slog.Info("importing ecosystem", "ecosystem", ecosystem)
		start := time.Now()
		// remove all affected packages for this ecosystem
		err := s.affectedCmpRepository.DeleteAll(ctx, nil, ecosystem)
		if err != nil {
			slog.Error("could not delete affected packages", "err", err)
			continue
		}
		slog.Info("deleted all affected packages", "ecosystem", ecosystem, "duration", time.Since(start))

		// download the zip and extract it in memory
		zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
		if err != nil {
			slog.Error("could not read zip", "err", err)
			continue
		}
		if len(zipReader.File) == 0 {
			slog.Error("no files found in zip")
			continue
		}

		// iterate over all files in the zip
		for _, file := range zipReader.File {
			// read the file
			unzippedFileBytes, err := utils.ReadZipFile(file)
			if err != nil {
				slog.Error("could not read file", "err", err, "file", file.Name)
				continue
			}

			osv := dtos.OSV{}
			err = json.Unmarshal(unzippedFileBytes, &osv)
			if err != nil {
				slog.Error("could not unmarshal osv", "err", err)
				continue
			}

			// if we do not support the Vulnerability Ecosystem we do not want to handle it
			if shouldIgnoreVulnerabilityID(osv.ID) {
				continue
			}

			// first build the CVE based on the OSV and save it to the db
			tx := s.cveRepository.Begin(ctx)
			defer tx.Rollback()

			relations := transformer.OSVToCVERelationships(&osv)

			err = s.cveRelationshipRepository.SaveBatch(ctx, tx, relations)
			if err != nil {
				slog.Error("could not save cve relation", "error", err)
				tx.Rollback()
				continue
			}

			newCVE := transformer.OSVToCVE(&osv)

			err = s.cveRepository.CreateCVEWithConflictHandling(ctx, tx, &newCVE)
			if err != nil {
				slog.Error("could not save CVE", "CVE", newCVE.CVE, "error", err)
				tx.Rollback()
				continue
			}

			affectedComponents := transformer.AffectedComponentsFromOSV(&osv, relations)

			// then create the affected components
			err = s.affectedCmpRepository.CreateAffectedComponentsUsingUnnest(ctx, tx, affectedComponents)
			if err != nil {
				slog.Error("could not save affected components", "cve", newCVE.CVE, "error", err)
				tx.Rollback()
				continue
			}

			err = s.cveRepository.CreateCVEAffectedComponentsEntries(ctx, tx, &newCVE, affectedComponents)
			if err != nil {
				slog.Error("could not save to cve_affected_components relation table", "cve", newCVE.CVE, "error", err)
				tx.Rollback()
				continue
			}
			tx.Commit()
		}

	}
	return nil
}

const numberOfFetcherRoutines = 120

func (s osvService) ImportRC(ctx context.Context) error {
	slog.Info("start RC import")
	// if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", "2026-04-01T17:00:14.778929Z"); err != nil {
	// 	return fmt.Errorf("could not update last import time: %w", err)
	// }
	var lastUpdate string
	var idsPerEcosystem map[string][]string
	err := s.configService.GetJSONConfig(ctx, "vulndb.lastRCImport", &lastUpdate)
	if err != nil {
		slog.Warn("could not get last RC import timestamp, assuming no import took place yet", "err", err)
		idsPerEcosystem, err = s.getRecentlyChangedIDsPerEcosystem(nil)
	} else {
		lastUpdateTimestamp, err := time.Parse(time.RFC3339Nano, lastUpdate)
		if err != nil {
			return fmt.Errorf("could not parse config timestamp: %w", err)
		}
		idsPerEcosystem, err = s.getRecentlyChangedIDsPerEcosystem(&lastUpdateTimestamp)
	}
	if err != nil {
		return err
	}
	// track the time right before fetching the data
	importStart := time.Now()

	slog.Info("calculated recently changed ids", "amount of ecosystem", len(idsPerEcosystem))

	// calculate the work load
	totalCount := 0
	for _, ids := range idsPerEcosystem {
		totalCount += len(ids)
	}

	waitGroup := &sync.WaitGroup{}
	jobs := make(chan fetchingJob, 5000)
	vulnData := make(chan dtos.OSV, 500)

	fetchingStart := time.Now()

	// fetch the data for each id
	for range numberOfFetcherRoutines {
		waitGroup.Add(1)
		go fetchOSVDataWorker(waitGroup, s.httpClient, jobs, vulnData)
	}

	// build the jobs for the fetching workers
	go s.fetchingController(waitGroup, jobs, idsPerEcosystem, vulnData)

	go func() {
		waitGroup.Wait()
		close(vulnData)
	}()

	// collect all OSV objects first
	allOSVVulns := make([]dtos.OSV, 0, totalCount)
	cveIDs := make([]string, 0, totalCount)
	for osvObject := range vulnData {
		cveIDs = append(cveIDs, osvObject.ID)
		allOSVVulns = append(allOSVVulns, osvObject)
	}
	slog.Info("finished collecting results start processing osv data", "fetching time", time.Since(fetchingStart))

	// then just pass the entries to the database for processing
	slog.Info("start database processing")
	dbStart := time.Now()
	err = s.processEntries(ctx, cveIDs, allOSVVulns)
	if err != nil {
		return fmt.Errorf("could process new OSV data, error: %w", err)
	}
	slog.Info("successfully processed data to database", "time elapsed", time.Since(dbStart))
	// lastly update the import to the earliest possible fetch
	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", importStart.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	return nil
}

// controls in what order and what method to use for each ecosystem
func (s osvService) fetchingController(waitGroup *sync.WaitGroup, jobs chan fetchingJob, idsPerEcosystem map[string][]string, output chan dtos.OSV) {
	defer close(jobs)

	// sort the ecosystems by the amount of changes for better concurrency performance (heavy zip downloads get called first)
	ecosystems := make([]string, 0, len(idsPerEcosystem))
	for ecosystem := range idsPerEcosystem {
		ecosystems = append(ecosystems, ecosystem)
	}
	slices.SortFunc(ecosystems, func(a, b string) int {
		return len(idsPerEcosystem[b]) - len(idsPerEcosystem[a])
	})

	for _, ecosystem := range ecosystems {
		ids := idsPerEcosystem[ecosystem]
		// when fetching too many entries in an ecosystem, switch to downloading the full zip and filtering instead
		if len(ids) >= 5000 {
			slog.Info("start fetching via zip", "ecosystem", ecosystem, "amount", len(ids))
			waitGroup.Add(1)
			go s.fetchEcosystemEntriesViaZip(waitGroup, ecosystem, ids, output)
		} else {
			// otherwise stick to getting each vuln separately
			slog.Info("start creating jobs for ecosystem", "ecosystem", ecosystem, "amount", len(ids))
			for _, id := range ids {
				if !shouldIgnoreVulnerabilityID(id) {
					jobs <- fetchingJob{Ecosystem: ecosystem, ID: id}
				}
			}
		}

	}
	slog.Info("finished pushing all jobs")
}

func (s osvService) fetchEcosystemEntriesViaZip(waitGroup *sync.WaitGroup, ecosystem string, idsToFetch []string, output chan dtos.OSV) {
	start := time.Now()

	zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
	if err != nil {
		slog.Error("could not read zip", "err", err, "ecosystem", ecosystem)
		return
	}
	if len(zipReader.File) == 0 {
		slog.Error("no files found in zip", "ecosystem", ecosystem)
	}

	shouldProcessID := make(map[string]struct{}, len(idsToFetch))
	for i := range idsToFetch {
		shouldProcessID[idsToFetch[i]] = struct{}{}
	}

	foundIDs := make(map[string]struct{}, len(idsToFetch))
	for i := range zipReader.File {
		readCloser, err := zipReader.File[i].Open()
		if err != nil {
			slog.Error("could not open osv file", "file", zipReader.File[i].Name, "err", err)
			continue
		}

		// only read the id and then decide if we need to further process it
		var partial struct {
			ID string `json:"id"`
		}

		// read until we find the id
		if err = json.NewDecoder(readCloser).Decode(&partial); err != nil {
			readCloser.Close()
			slog.Error("could not parse osv id", "file", zipReader.File[i].Name, "err", err)
			continue
		}
		readCloser.Close()

		// check if we need to process this file and if we need to continue
		if _, ok := shouldProcessID[partial.ID]; !ok {
			// not relevant -> skip entry
			continue
		}

		// we want to process the file so we need to fully read it now
		osvEntry := dtos.OSV{}
		readCloserFull, err := zipReader.File[i].Open()
		if err != nil {
			slog.Error("could not open osv file", "file", zipReader.File[i].Name, "err", err)
			continue
		}

		if err = json.NewDecoder(readCloserFull).Decode(&osvEntry); err != nil {
			readCloserFull.Close()
			slog.Error("could not parse osv file to OSV dto", "file", zipReader.File[i].Name, "err", err)
			continue
		}
		readCloserFull.Close()
		output <- osvEntry

		// sanity check with a deduplicated set of ids
		foundIDs[osvEntry.ID] = struct{}{}
		if len(foundIDs) == len(idsToFetch) {
			break
		}
	}
	waitGroup.Done()
	slog.Info("finished processing zip", "ecosystem", ecosystem, "time elapsed", time.Since(start))
}

type fetchingJob struct {
	Ecosystem string
	ID        string
}

func fetchOSVDataWorker(waitGroup *sync.WaitGroup, client *http.Client, jobs chan fetchingJob, output chan dtos.OSV) {
	for job := range jobs {
		url := fmt.Sprintf("https://storage.googleapis.com/osv-vulnerabilities/%s/%s.json", job.Ecosystem, job.ID)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			slog.Error("could not build http request to fetch osv data", "err", err, "url", url)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			slog.Error("could not fetch osv data via http request", "err", err, "url", url)
			continue
		}

		osvVuln := dtos.OSV{}
		if err = json.NewDecoder(resp.Body).Decode(&osvVuln); err != nil {
			resp.Body.Close()
			slog.Error("could not parse osv file to OSV dto", "file", "OSV ID", job.ID, "err", err, "url", url)
			continue
		}
		resp.Body.Close()
		output <- osvVuln
	}
	waitGroup.Done()
}

func deleteEntries(tx *gorm.DB, cveIDs []string) error {
	// first delete all entries related to the updated entries
	err := tx.Exec(`DELETE FROM cve_affected_component WHERE cvecve = ANY($1::text[]);`, pq.Array(cveIDs)).Error
	if err != nil {
		return fmt.Errorf("could not delete cve_affected_component, aborting transaction: %w", err)
	}

	err = tx.Exec(`DELETE FROM cve_relationships WHERE source_cve = ANY($1::text[]);`, pq.Array(cveIDs)).Error
	if err != nil {
		return fmt.Errorf("could not delete cve_relationships, aborting transaction: %w", err)
	}

	err = tx.Exec(`DELETE FROM cves WHERE cve = ANY($1::text[]);`, pq.Array(cveIDs)).Error
	if err != nil {
		return fmt.Errorf("could not delete cves entries aborting transaction: %w", err)
	}
	return nil
}

// fetches the list of all recent changes and returns a map of recent changes for each ecosystem
func (s osvService) getRecentlyChangedIDsPerEcosystem(lastUpdate *time.Time) (map[string][]string, error) {
	closed := false

	// first get all the recent changes from the osv API
	req, err := http.NewRequest(http.MethodGet, osvBaseURL+"/modified_id.csv", nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	resp, err := s.httpClient.Do(req)
	defer func() {
		if !closed {
			resp.Body.Close()
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("csv fetch http request ran into errors: error=%w ecosystem=%s", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("csv fetch was unsuccessful: status=%d ecosystem=%s", resp.StatusCode)
	}

	records, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "could not read csv")
	}

	// we read everything from the body so we can close it and mark it as closed
	resp.Body.Close()
	closed = true

	// now we can map the changed OSV ID to its ecosystem
	idsPerEcosystem := make(map[string][]string, len(importEcosystems))

	// use a map to process each vuln only once
	alreadyProcessed := make(map[string]struct{}, 1<<14)
	for _, record := range records {
		if len(record) != 2 {
			slog.Warn("invalid cvs row format skipping entry")
			continue
		}
		// each row in the csv file consists of the entryTimestamp in the first column and the id in the second column (record[0] and record[1] respectively)
		entryTimestamp, err := time.Parse(time.RFC3339Nano, record[0])
		if err != nil {
			return nil, fmt.Errorf("could not parse timestamp from csv first row: %w", err)
		}
		// entries are sorted descending by timestamp; only process changes which happened after our latest update
		if lastUpdate != nil && entryTimestamp.Before(*lastUpdate) {
			break
		}

		ecosystem, id, found := strings.Cut(record[1], "/")
		if !found {
			return nil, fmt.Errorf("invalid format for vuln id", "id column", record[1])
		}

		if !slices.Contains(importEcosystems, ecosystem) || shouldIgnoreVulnerabilityID(id) {
			// we do not support this ecosystem -> skip to next one
			continue
		}

		// lastly check if we have already seen this vuln
		if _, ok := alreadyProcessed[id]; !ok {
			idsPerEcosystem[ecosystem] = append(idsPerEcosystem[ecosystem], id)
			alreadyProcessed[id] = struct{}{}
		}
	}
	return idsPerEcosystem, nil
}

func (s osvService) getOSVObjectsFromIDs(ecosystem string, ids map[string]struct{}) ([]dtos.OSV, error) {
	zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)
	if err != nil {
		slog.Error("could not read zip", "err", err)
		return nil, err
	}
	if len(zipReader.File) == 0 {
		slog.Error("no files found in zip")
		return nil, fmt.Errorf("no files found in zip")
	}

	entries := make([]dtos.OSV, 0, len(ids))
	foundIDs := make(map[string]struct{}, len(ids))
	for i := range zipReader.File {
		readCloser, err := zipReader.File[i].Open()
		if err != nil {
			slog.Error("could not open osv file", "file", zipReader.File[i].Name, "err", err)
			continue
		}

		// only read the id and then decide if we need to further process it
		var partial struct {
			ID string `json:"id"`
		}

		// read until we find the id
		if err = json.NewDecoder(readCloser).Decode(&partial); err != nil {
			readCloser.Close()
			slog.Error("could not parse osv id", "file", zipReader.File[i].Name, "err", err)
			continue
		}
		readCloser.Close()

		// check if we need to process this file and if we need to continue
		if _, ok := ids[partial.ID]; !ok {
			// not relevant -> skip entry
			continue
		}

		// we want to process the file so we need to fully read it now
		osvEntry := dtos.OSV{}
		readCloserFull, err := zipReader.File[i].Open()
		if err != nil {
			slog.Error("could not open osv file", "file", zipReader.File[i].Name, "err", err)
			continue
		}

		if err = json.NewDecoder(readCloserFull).Decode(&osvEntry); err != nil {
			readCloserFull.Close()
			slog.Error("could not parse osv file to OSV dto", "file", zipReader.File[i].Name, "err", err)
			continue
		}
		readCloserFull.Close()
		entries = append(entries, osvEntry)
		// sanity check with a deduplicated set of ids
		foundIDs[osvEntry.ID] = struct{}{}
		if len(foundIDs) == len(ids) {
			break
		}
	}
	return entries, nil
}

// execute all necessary steps to insert new entries and update the existing ones
func (s osvService) processEntries(ctx context.Context, cveIDs []string, allEntries []dtos.OSV) error {
	// get the current state of the affected components
	currentCVEAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*5)
	err := s.affectedCmpRepository.GetDB(ctx, nil).Raw(`SELECT * FROM cve_affected_component WHERE cvecve = ANY($1::text[])`, pq.Array(cveIDs)).Find(&currentCVEAffectedComponents).Error
	if err != nil {
		return fmt.Errorf("could not get current state of affected components: %w", err)
	}

	// build a map of the current state for Bulk lookups
	isAffectedComponentPresent := make(map[string]struct{}, len(currentCVEAffectedComponents))
	for _, cveAffectedComponent := range currentCVEAffectedComponents {
		isAffectedComponentPresent[cveAffectedComponent.AffectedComponentID] = struct{}{}
	}

	cves := make([]models.CVE, 0, len(allEntries))
	cveRelationships := make([]models.CVERelationship, 0, len(allEntries))
	affectedComponents := make([]models.AffectedComponent, 0, len(allEntries)*15) // assume each cve has 3 affected components

	cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*55) // key -> key
	slog.Info("start building rows", "amount", len(allEntries))
	buildingTime := time.Now()
	// built all the objects first
	for i := range allEntries {
		cve := transformer.OSVToCVE(&allEntries[i])

		cves = append(cves, cve)

		relationships := transformer.OSVToCVERelationships(&allEntries[i])
		cveRelationships = append(cveRelationships, relationships...)

		affectedComponentsForCVE := transformer.AffectedComponentsFromOSV(&allEntries[i], relationships)
		if len(affectedComponentsForCVE) == 0 {
			continue // 20k + empty CVEs -> ignore them completely?
		}

		isCVEAffectedComponentAlreadyPresent := make(map[cveAffectedComponentRow]struct{}, 512)
		for _, affectedComponent := range affectedComponentsForCVE {
			hash := affectedComponent.CalculateHashFast()
			affectedComponent.ID = hash // assign hash for later use
			row := cveAffectedComponentRow{CveCVE: cve.CVE, AffectedComponentID: hash}
			if _, ok := isAffectedComponentPresent[hash]; !ok {
				affectedComponents = append(affectedComponents, affectedComponent)
				// add the new component, so that we do not have duplicates in the new data
				isAffectedComponentPresent[hash] = struct{}{}
			}
			if _, ok := isCVEAffectedComponentAlreadyPresent[row]; !ok {
				cveAffectedComponents = append(cveAffectedComponents, row)
				// add the new component, so that we do not have duplicates in the new data
				isCVEAffectedComponentAlreadyPresent[row] = struct{}{}
			}
		}
	}

	allEntries = nil
	cveIDs = nil

	slog.Info("finished building rows", "building time", time.Since(buildingTime))

	const batchSize = 2000
	const copyThreshold = 42_000

	// gorm tx handles CVEs + cve_relationships (ORM-friendly, per-row ON CONFLICT DO NOTHING).
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could acquire postgresql connection: %w", err)
	}
	defer conn.Conn().Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const bulkThreshold = 50_000

	// full bulk insert over this threshold
	if len(cves) > bulkThreshold {
		err = prepareBulkInsert(ctx, tx)
		if err != nil {
			return fmt.Errorf("could not prepare transaction: %w", err)
		}

		err = insertCVEsBulk(ctx, tx, cves)
		if err != nil {
			return fmt.Errorf("could not insert cves: %w", err)
		}

		err = insertCVERelationshipsBulk(ctx, tx, cveRelationships)
		if err != nil {
			return fmt.Errorf("could not insert cve relationships: %w", err)
		}

		err = insertAffectedComponentsBulk(ctx, tx, affectedComponents)
		if err != nil {
			return fmt.Errorf("could not insert affected_components: %w", err)
		}
		if err := insertCVEAffectedComponentsBulk(ctx, tx, cveAffectedComponents); err != nil {
			return fmt.Errorf("could not insert cve_affected_component: %w", err)
		}

		// now we finished inserting all data and need to reassign the constraints on the tables and rebuild the indexes
		err = addIndexesAndConstraints(ctx, tx)
		if err != nil {
			return fmt.Errorf("could not re-add constraints and indexes on table: %w", err)
		}
	} else {
		// below the threshold normal imports is faster
		slog.Info("below threshold will try diff update")
		startInsertCVEs := time.Now()
		err = insertCVEsNormal(ctx, tx, cves)
		if err != nil {
			return fmt.Errorf("could not insert cves: %w", err)
		}
		slog.Info("finished inserting cves", "time", time.Since(startInsertCVEs))

		startInsertCVERelationships := time.Now()
		err = insertCVERelationshipsNormal(ctx, tx, cveRelationships)
		if err != nil {
			return fmt.Errorf("could not insert cve relationships: %w", err)
		}
		slog.Info("finished inserting cve relationships", "time", time.Since(startInsertCVERelationships))

		startInsertAffectedComponents := time.Now()
		err = insertAffectedComponentsBulk(ctx, tx, affectedComponents)
		if err != nil {
			return fmt.Errorf("could not insert affected_components: %w", err)
		}
		slog.Info("finished inserting affected components", "time", time.Since(startInsertAffectedComponents))

		startCVEAffectedComponents := time.Now()
		if err := insertCVEAffectedComponentsBulk(ctx, tx, cveAffectedComponents); err != nil {
			return fmt.Errorf("could not insert cve_affected_component: %w", err)
		}
		slog.Info("finished inserting cve affected components", "time", time.Since(startCVEAffectedComponents))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}
	return nil
}

func areCVEsIdentical(c1, c2 models.CVE) bool {
	return c1.CVE == c2.CVE && c1.DatePublished == c2.DatePublished && c1.DateLastModified == c2.DateLastModified && c1.Description == c2.Description && c1.CVSS == c2.CVSS && c1.Vector == c2.Vector
}

type cveAffectedComponentRow struct {
	CveCVE              string `gorm:"column:cvecve"`
	AffectedComponentID string `gorm:"column:affected_component_id"`
}

func insertCVEsBulk(ctx context.Context, tx pgx.Tx, cves []models.CVE) error {
	slog.Info("inserting into cves using bulk insert", "amount", len(cves))
	start := time.Now()
	columnNames := []string{"cve", "created_at", "updated_at", "date_published", "date_last_modified", "description", "cvss", "references", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile", "vector"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cves"}, columnNames, pgx.CopyFromSlice(len(cves), func(i int) ([]interface{}, error) {
		row := cves[i]
		return []interface{}{row.CVE, row.CreatedAt, row.UpdatedAt, row.DatePublished, row.DateLastModified, row.Description, row.CVSS, row.References, row.CISAExploitAdd, row.CISAActionDue, row.CISARequiredAction, row.CISAVulnerabilityName, row.EPSS, row.Percentile, row.Vector}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve rows into table: %w", err)
	}
	slog.Info("finished inserting into cves", "time", time.Since(start))
	return nil
}

func insertCVERelationshipsBulk(ctx context.Context, tx pgx.Tx, cveRelationships []models.CVERelationship) error {
	slog.Info("inserting into cve_relationships using bulk insert", "amount", len(cveRelationships))
	start := time.Now()
	columnNames := []string{"target_cve", "source_cve", "relationship_type"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_relationships"}, columnNames, pgx.CopyFromSlice(len(cveRelationships), func(i int) ([]interface{}, error) {
		row := cveRelationships[i]
		return []interface{}{row.TargetCVE, row.SourceCVE, row.RelationshipType}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve relationship rows into table: %w", err)
	}
	slog.Info("finished inserting into cve_relationships", "time", time.Since(start))
	return nil
}

func insertAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, components []models.AffectedComponent) error {
	slog.Info("inserting into affected_components using bulk insert", "amount", len(components))
	start := time.Now()
	// pgx has no built-in codec for the custom semver type, so stage as text
	// and cast during the INSERT ... SELECT.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE affected_components_stage (
			id                 text,
			source             text,
			purl               text,
			ecosystem          text,
			scheme             text,
			type               text,
			name               text,
			namespace          text,
			qualifiers         jsonb,
			subpath            text,
			version            text,
			semver_introduced  text,
			semver_fixed       text,
			version_introduced text,
			version_fixed      text
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("could not create staging table: %w", err)
	}

	columnNames := []string{"id", "source", "purl", "ecosystem", "scheme", "type", "name", "namespace", "qualifiers", "subpath", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"affected_components_stage"}, columnNames, pgx.CopyFromSlice(len(components), func(i int) ([]interface{}, error) {
		c := components[i]
		qualifiers := "{}"
		if c.Qualifiers != nil {
			b, err := json.Marshal(c.Qualifiers)
			if err != nil {
				return nil, fmt.Errorf("marshal qualifiers: %w", err)
			}
			qualifiers = string(b)
		}
		return []interface{}{c.ID, c.Source, c.PurlWithoutVersion, c.Ecosystem, c.Scheme, c.Type, c.Name, c.Namespace, qualifiers, c.Subpath, c.Version, c.SemverIntroduced, c.SemverFixed, c.VersionIntroduced, c.VersionFixed}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy affected component rows into staging table: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO affected_components (
			id, source, purl, ecosystem, scheme, type, name,
			namespace, qualifiers, subpath, version,
			semver_introduced, semver_fixed,
			version_introduced, version_fixed
		)
		SELECT
			id, source, purl, ecosystem, scheme, type, name,
			namespace, qualifiers, subpath, version,
			semver_introduced::semver, semver_fixed::semver,
			version_introduced, version_fixed
		FROM affected_components_stage`); err != nil {
		return fmt.Errorf("could not insert from staging into affected_components: %w", err)
	}
	slog.Info("finished inserting into affected_components", "time", time.Since(start))
	return nil
}

func insertCVEAffectedComponentsBulk(ctx context.Context, tx pgx.Tx, pivotRows []cveAffectedComponentRow) error {
	slog.Info("inserting into cve_affected_component using bulk insert", "amount", len(pivotRows))
	start := time.Now()
	columnNames := []string{"affected_component_id", "cvecve"}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_affected_component"}, columnNames, pgx.CopyFromSlice(len(pivotRows), func(i int) ([]interface{}, error) {
		row := pivotRows[i]
		return []interface{}{row.AffectedComponentID, row.CveCVE}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy cve affected component rows into table: %w", err)
	}
	slog.Info("finished inserting into cve_affected_component", "time", time.Since(start))
	return nil
}

func insertCVEsNormal(ctx context.Context, tx pgx.Tx, cves []models.CVE) error {
	if len(cves) == 0 {
		return nil
	}

	ids := make([]string, len(cves))
	createdAts := make([]time.Time, len(cves))
	updatedAts := make([]time.Time, len(cves))
	datePublisheds := make([]time.Time, len(cves))
	dateLastModifieds := make([]time.Time, len(cves))
	descriptions := make([]string, len(cves))
	cvsss := make([]float32, len(cves))
	references := make([]string, len(cves))
	cisaExploitAdds := make([]any, len(cves))
	cisaActionDues := make([]any, len(cves))
	cisaRequiredActions := make([]string, len(cves))
	cisaVulnerabilityNames := make([]string, len(cves))
	epsss := make([]any, len(cves))
	percentiles := make([]any, len(cves))
	vectors := make([]string, len(cves))

	now := time.Now()
	for i := range cves {
		ids[i] = cves[i].CVE
		if cves[i].CreatedAt.IsZero() {
			createdAts[i] = now
		} else {
			createdAts[i] = cves[i].CreatedAt
		}
		if cves[i].UpdatedAt.IsZero() {
			updatedAts[i] = now
		} else {
			updatedAts[i] = cves[i].UpdatedAt
		}
		datePublisheds[i] = cves[i].DatePublished
		dateLastModifieds[i] = cves[i].DateLastModified
		descriptions[i] = cves[i].Description
		cvsss[i] = cves[i].CVSS
		references[i] = cves[i].References
		if cves[i].CISAExploitAdd != nil {
			cisaExploitAdds[i] = time.Time(*cves[i].CISAExploitAdd).Format("2006-01-02")
		}
		if cves[i].CISAActionDue != nil {
			cisaActionDues[i] = time.Time(*cves[i].CISAActionDue).Format("2006-01-02")
		}
		cisaRequiredActions[i] = cves[i].CISARequiredAction
		cisaVulnerabilityNames[i] = cves[i].CISAVulnerabilityName
		if cves[i].EPSS != nil {
			epsss[i] = *cves[i].EPSS
		}
		if cves[i].Percentile != nil {
			percentiles[i] = *cves[i].Percentile
		}
		vectors[i] = cves[i].Vector
	}

	sql := `INSERT INTO cves (cve, created_at, updated_at, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector)
	SELECT
		unnest($1::text[]),
		unnest($2::timestamptz[]),
		unnest($3::timestamptz[]),
		unnest($4::timestamptz[]),
		unnest($5::timestamptz[]),
		unnest($6::text[]),
		unnest($7::numeric(4,2)[]),
		unnest($8::text[]),
		unnest($9::text[])::date,
		unnest($10::text[])::date,
		unnest($11::text[]),
		unnest($12::text[]),
		unnest($13::text[])::numeric(6,5),
		unnest($14::text[])::numeric(6,5),
		unnest($15::text[])
	ON CONFLICT (cve) DO NOTHING`

	_, err := tx.Exec(ctx, sql,
		ids,
		createdAts,
		updatedAts,
		datePublisheds,
		dateLastModifieds,
		descriptions,
		cvsss,
		references,
		cisaExploitAdds,
		cisaActionDues,
		cisaRequiredActions,
		cisaVulnerabilityNames,
		epsss,
		percentiles,
		vectors,
	)
	if err != nil {
		return fmt.Errorf("could not insert cves: %w", err)
	}
	return nil
}

func insertCVERelationshipsNormal(ctx context.Context, tx pgx.Tx, relationships []models.CVERelationship) error {
	if len(relationships) == 0 {
		return nil
	}

	sourceCVEs := make([]string, len(relationships))
	targetCVEs := make([]string, len(relationships))
	relationshipTypes := make([]string, len(relationships))

	for i := range relationships {
		sourceCVEs[i] = relationships[i].SourceCVE
		targetCVEs[i] = relationships[i].TargetCVE
		relationshipTypes[i] = string(relationships[i].RelationshipType)
	}

	sql := `INSERT INTO cve_relationships (source_cve, target_cve, relationship_type)
	SELECT
		unnest($1::text[]),
		unnest($2::text[]),
		unnest($3::text[])
	ON CONFLICT (source_cve, target_cve, relationship_type) DO NOTHING`

	_, err := tx.Exec(ctx, sql, sourceCVEs, targetCVEs, relationshipTypes)
	if err != nil {
		return fmt.Errorf("could not insert cve_relationships: %w", err)
	}
	return nil
}

func prepareBulkInsert(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
	SET LOCAL synchronous_commit = OFF; -- this makes postgresql return as soon as the WAL has been written to and we do not need to wait until the contents have been written to the disk

	-- first drop all foreign key constraints between the tables since they depend on the primary keys
	ALTER TABLE public.cve_relationships DROP CONSTRAINT IF EXISTS fk_cve_relationships_source;

	ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_affected_component;
	ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;
	
	-- need to be dropped before dropping cves_pkey
	ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve; 
	ALTER TABLE public.exploits DROP CONSTRAINT IF EXISTS fk_cves_exploits;
	ALTER TABLE public.weaknesses DROP CONSTRAINT IF EXISTS fk_cves_weaknesses;
	ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS fk_vex_rules_cve;

	-- then drop all primary key constraints
	ALTER TABLE public.cves DROP CONSTRAINT IF EXISTS cves_pkey;
	ALTER TABLE affected_components DROP CONSTRAINT IF EXISTS affected_components_pkey;
	ALTER TABLE public.cve_relationships DROP CONSTRAINT IF EXISTS cve_relationships_pkey;
	ALTER TABLE cve_affected_component DROP CONSTRAINT IF EXISTS cve_affected_component_pkey;
	
	-- lastly drop all indexes 
	DROP INDEX IF EXISTS idx_affected_components_semver_fixed;
    DROP INDEX IF EXISTS idx_affected_components_semver_introduced;
    DROP INDEX IF EXISTS idx_affected_components_version_fixed;
    DROP INDEX IF EXISTS idx_affected_components_version_introduced;
    DROP INDEX IF EXISTS idx_affected_components_p_url;
    DROP INDEX IF EXISTS idx_affected_components_purl_without_version;
    DROP INDEX IF EXISTS idx_affected_components_version;

	DROP INDEX IF EXISTS cve_affected_component_affected_component_id;

	DROP INDEX IF EXISTS idx_cve_relationships_target_cve;`)
	if err != nil {
		return fmt.Errorf("could not drop indexes and constraints on tables: %w", err)
	}
	return nil
}

func addIndexesAndConstraints(ctx context.Context, tx pgx.Tx) error {
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
	ALTER TABLE public.cves ADD CONSTRAINT cves_pkey PRIMARY KEY (cve);
	ALTER TABLE affected_components ADD CONSTRAINT affected_components_pkey PRIMARY KEY (id);
	ALTER TABLE public.cve_relationships ADD CONSTRAINT cve_relationships_pkey PRIMARY KEY (target_cve, source_cve, relationship_type);
	ALTER TABLE cve_affected_component ADD CONSTRAINT cve_affected_component_pkey PRIMARY KEY (affected_component_id,cvecve);
	`)
	if err != nil {
		return fmt.Errorf("could not apply primary key constraints: %w", err)
	}
	slog.Info("finished adding primary key constraints", "time", time.Since(totalStart))

	start := time.Now()
	_, err = tx.Exec(ctx, `
	-- Then add the foreign key constraints
	ALTER TABLE public.cve_relationships ADD CONSTRAINT fk_cve_relationships_source FOREIGN KEY (source_cve) REFERENCES public.cves (cve) ON DELETE CASCADE NOT VALID;

	ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_affected_component FOREIGN KEY (affected_component_id) REFERENCES public.affected_components (id) ON DELETE CASCADE NOT VALID;

	ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_cve FOREIGN KEY (cvecve) REFERENCES public.cves (cve) ON DELETE CASCADE NOT VALID;
	ALTER TABLE public.dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE; 
	ALTER TABLE public.exploits ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;
	ALTER TABLE ONLY public.weaknesses ADD CONSTRAINT fk_cves_weaknesses FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
	ALTER TABLE public.vex_rules ADD CONSTRAINT fk_vex_rules_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;`)
	if err != nil {
		return fmt.Errorf("could not apply foreign key constraints: %w", err)
	}
	slog.Info("finsihed applying all foreign key constraints", "time", time.Since(start))

	start = time.Now()
	_, err = tx.Exec(ctx, `
	-- Lastly rebuild the indexes
    CREATE INDEX IF NOT EXISTS cve_affected_component_affected_component_id ON public.cve_affected_component USING hash (cvecve);

    CREATE INDEX IF NOT EXISTS idx_affected_components_semver_fixed ON public.affected_components USING btree (semver_fixed);
    CREATE INDEX IF NOT EXISTS idx_affected_components_semver_introduced ON public.affected_components USING btree (semver_introduced);
    CREATE INDEX IF NOT EXISTS idx_affected_components_version_fixed ON public.affected_components USING btree (version_fixed);
    CREATE INDEX IF NOT EXISTS idx_affected_components_version_introduced ON public.affected_components USING btree (version_introduced);
    CREATE INDEX IF NOT EXISTS idx_affected_components_purl_without_version ON public.affected_components USING btree (purl);
	CREATE INDEX IF NOT EXISTS idx_affected_components_version ON public.affected_components USING btree (version);`)
	if err != nil {
		return fmt.Errorf("could not build indexes: %w", err)
	}
	slog.Info("finsihed building all indexes", "time", time.Since(start))
	slog.Info("finished adding constraints and building indexes", "time", time.Since(totalStart))
	return nil
}
