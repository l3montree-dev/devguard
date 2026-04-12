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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
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
	"Linux",
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
		slog.Info("start waiting for go routines to finish")
		waitGroup.Wait()
		slog.Info("fetching routines done, closing results")
		close(vulnData)
	}()

	slog.Info("start collecting results")
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
	slog.Info("start fetching via zip", "ecosystem", ecosystem, "amount", len(idsToFetch))
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

	if len(shouldProcessID) == len(idsToFetch) {
		slog.Info("no duplicates all fine")
	} else {
		slog.Warn("NO DUPLICATES SHOULD BE FOUND")
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

var pMutext = sync.Mutex{}
var totalProcessed = 0

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

		pMutext.Lock()
		totalProcessed++
		if totalProcessed%10000 == 0 {
			slog.Info("processed entries", totalProcessed)
		}
		pMutext.Unlock()
	}
	waitGroup.Done()
}

// execute all necessary steps to insert new entries and update the existing ones
func (s osvService) processEntries(ctx context.Context, cveIDs []string, allEntries []dtos.OSV) error {
	// get the current state of the affected components
	currentCVEAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*5)
	err := s.affectedCmpRepository.GetDB(ctx, nil).Raw(`SELECT * FROM cve_affected_component WHERE cvecve = ANY($1::text[])`, pq.Array(cveIDs)).Find(&currentCVEAffectedComponents).Error
	if err != nil {
		return fmt.Errorf("could not get current state of affected components: %w", err)
	}

	// build a map of the current state for fast lookups
	isAffectedComponentPresent := make(map[string]struct{}, len(currentCVEAffectedComponents))
	isCVEAffectedComponentPresent := make(map[cveAffectedComponentRow]struct{}, len(currentCVEAffectedComponents))
	for _, cveAffectedComponent := range currentCVEAffectedComponents {
		isAffectedComponentPresent[cveAffectedComponent.AffectedComponentID] = struct{}{}
		isCVEAffectedComponentPresent[cveAffectedComponent] = struct{}{}
	}

	cves := make([]models.CVE, 0, len(allEntries))
	cveRelationships := make([]models.CVERelationship, 0, len(allEntries))
	affectedComponents := make([]models.AffectedComponent, 0, len(allEntries)*3) // assume each cve has 3 affected components

	cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(allEntries)*3) // key -> key

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
		for _, affectedComponent := range affectedComponentsForCVE {
			hash := affectedComponent.CalculateHash()
			row := cveAffectedComponentRow{CveCVE: cve.CVE, AffectedComponentID: hash}
			if _, ok := isAffectedComponentPresent[hash]; !ok {
				affectedComponents = append(affectedComponents, affectedComponent)
				// add the new component, so that we do not have duplicates in the new data
				isAffectedComponentPresent[hash] = struct{}{}
			}
			if _, ok := isCVEAffectedComponentPresent[row]; !ok {
				cveAffectedComponents = append(cveAffectedComponents, cveAffectedComponentRow{
					CveCVE:              cve.CVE,
					AffectedComponentID: hash, // can access the id directly since we set it previously in the loop
				})
				// add the new component, so that we do not have duplicates in the new data
				isCVEAffectedComponentPresent[row] = struct{}{}
			}
		}
	}
	allEntries = nil
	cveIDs = nil

	slog.Info("finished building rows", "building time", time.Since(buildingTime))

	const batchSize = 2000
	const copyThreshold = 42_000

	// gorm tx handles CVEs + cve_relationships (ORM-friendly, per-row ON CONFLICT DO NOTHING).
	gormTx := s.cveRepository.Begin(ctx)
	defer gormTx.Rollback()

	startInsertCVEs := time.Now()
	if err := gormTx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(cves, batchSize).Error; err != nil {
		return fmt.Errorf("could not insert cves: %w", err)
	}
	slog.Info("finished inserting cves", "time", time.Since(startInsertCVEs))

	startInsertCVERelationships := time.Now()
	if err := gormTx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(cveRelationships, batchSize).Error; err != nil {
		return fmt.Errorf("could not insert cve_relationships: %w", err)
	}
	slog.Info("finished inserting cve relationships", "time", time.Since(startInsertCVERelationships))

	startInsertAffectedComponents := time.Now()
	err = s.affectedCmpRepository.CreateAffectedComponentsUsingUnnest(ctx, gormTx, affectedComponents)
	if err != nil {
		return fmt.Errorf("could not insert affected_components: %w", err)
	}
	slog.Info("finished inserting affected components", "time", time.Since(startInsertAffectedComponents))

	startCVEAffectedComponents := time.Now()
	if err := s.InsertCVEAffectedComponentsEntries(ctx, gormTx, cveAffectedComponents); err != nil {
		return fmt.Errorf("could not insert cve_affected_component: %w", err)
	}
	slog.Info("finished inserting cve affected components", "time", time.Since(startCVEAffectedComponents))

	if err := gormTx.Commit().Error; err != nil {
		return fmt.Errorf("could not commit gorm transaction: %w", err)
	}
	return nil
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

	type ecosystemIDKey = struct{ Ecosystem, ID string }

	// use a map to process each ecosystem + vuln combo only once
	alreadyProcessed := make(map[ecosystemIDKey]struct{}, 1<<14)
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

		// lastly check if we already added it to the list
		key := ecosystemIDKey{Ecosystem: ecosystem, ID: id}
		if _, ok := alreadyProcessed[key]; !ok {
			idsPerEcosystem[ecosystem] = append(idsPerEcosystem[ecosystem], id)
			alreadyProcessed[key] = struct{}{}
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

type cveAffectedComponentRow struct {
	CveCVE              string `gorm:"column:cvecve"`
	AffectedComponentID string `gorm:"column:affected_component_id"`
}

func (s osvService) InsertCVEAffectedComponentsEntries(ctx context.Context, tx *gorm.DB, components []cveAffectedComponentRow) error {
	cveIDs := make([]string, len(components))
	affectedComponentIDs := make([]string, len(components))

	for i := range components {
		cveIDs[i] = components[i].CveCVE
		affectedComponentIDs[i] = components[i].AffectedComponentID
	}

	query := `INSERT INTO cve_affected_component (affected_component_id,cvecve) 
	SELECT 
	unnest($1::text[]),
	unnest($2::text[])
	ON CONFLICT DO NOTHING`

	return s.cveRepository.GetDB(ctx, tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Exec(query, affectedComponentIDs, cveIDs).Error
}
