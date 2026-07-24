// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/errgroup"
)

// minimal struct to omit unused fields and therefore improve parsing speed and memory consumption
type minimalCSAFAdvisory struct {
	Document        *minimalCSAFDocument `json:"document"`
	Vulnerabilities []*minimalCSAFVuln   `json:"vulnerabilities,omitempty"`
}

type minimalCSAFDocument struct {
	Notes    []*minimalCSAFNote   `json:"notes,omitempty"`
	Tracking *minimalCSAFTracking `json:"tracking"`
}

type minimalCSAFTracking struct {
	ID                 *string `json:"id"`
	CurrentReleaseDate *string `json:"current_release_date"`
	InitialReleaseDate *string `json:"initial_release_date"`
}

type minimalCSAFNote struct {
	Category *string `json:"category"`
	Text     *string `json:"text"`
	Title    *string `json:"title,omitempty"`
}

type minimalCSAFVuln struct {
	CVE *string `json:"cve,omitempty"`
}

type csafSource struct {
	name string
	url  string
}

// fixed order so the export is reproducible; do not derive this from a map
var csafSources = []csafSource{
	{name: "BSI", url: "https://wid.cert-bund.de/.well-known/csaf/white/"},
	{name: "NCSC", url: "https://advisories.ncsc.nl/csaf/v2/"},
}

func fetchAllCSAFSources(ctx context.Context) ([]models.CVE, error) {
	allCVEs := make([]models.CVE, 0, len(csafSources)*3000)
	for _, source := range csafSources {
		slog.Info("start fetching CSAF reports", "source", source.name)
		cves, err := FetchCSAFData(ctx, source.url)
		if err != nil {
			return nil, err
		}
		allCVEs = append(allCVEs, cves...)
	}
	return allCVEs, nil
}

// fetches the file of the job and parse it into a minimal CSAF struct
func fetchCSAFReportWorker(ctx context.Context, jobs chan string, output chan *minimalCSAFAdvisory, client *http.Client) error {
	for {
		select {
		case url, ok := <-jobs:
			if !ok { // channel closed we are done
				return nil
			}

			body, err := utils.DoGetRequestWithContext(ctx, url, client)
			if err != nil {
				return fmt.Errorf("could not fetch CSAF file at %s: %w", url, err)
			}

			var csafReport minimalCSAFAdvisory
			err = json.NewDecoder(body).Decode(&csafReport)
			body.Close()
			if err != nil {
				return fmt.Errorf("could not unmarshal json into csaf struct: %w", err)
			}

			select {
			case output <- &csafReport:
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// receives fetched CSAF advisories and converts them to cve objects, by extracting the necessary information
func convertCSAFReportToModelsWorker(ctx context.Context, jobs chan *minimalCSAFAdvisory, cvesOutput chan *models.CVE) error {
	for {
		select {
		case csafReport, ok := <-jobs:
			if !ok { // channel closed we are done
				return nil
			}
			if csafReport.Document == nil {
				return fmt.Errorf("invalid csaf document. document property is missing")
			}

			if len(csafReport.Vulnerabilities) == 0 {
				continue // no vulnerabilities means no relationships, that means it will never be found
			}

			tracking := csafReport.Document.Tracking // improve readability
			if tracking == nil || tracking.ID == nil {
				return fmt.Errorf("no id in tracking object can be found")
			}

			cve := models.CVE{CVE: string(*tracking.ID)} // the tracking ID is the CVE-ID in our database

			if tracking.InitialReleaseDate != nil {
				date, err := time.Parse(time.RFC3339Nano, *tracking.InitialReleaseDate)
				if err == nil {
					cve.DatePublished = date
				}
			}

			if tracking.CurrentReleaseDate != nil {
				date, err := time.Parse(time.RFC3339Nano, *tracking.CurrentReleaseDate)
				if err == nil {
					cve.DateLastModified = date
				}
			}

			cve.Description = buildCVEDesciptionFromCSAFNotes(csafReport.Document.Notes)
			cve.ID = cve.CalculateHash()
			cve.ContentHash = cve.CalculateContentHash()

			// each vulnerability associated with this advisory-id is a cve_relationship
			for _, vuln := range csafReport.Vulnerabilities {
				if vuln == nil || vuln.CVE == nil {
					continue
				}
				// the referenced official cve is the source_cve (it carries the fk on cves.cve), the advisory is the target_cve
				cve.Relationships = append(cve.Relationships, models.CVERelationship{
					SourceCVE:        string(*vuln.CVE),
					TargetCVE:        cve.CVE,
					RelationshipType: dtos.RelationshipTypeAdvisory, // use custom relationship type to distinguish them easily
				})
			}

			select {
			case cvesOutput <- &cve:
			case <-ctx.Done():
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// builds a textual description by combining different notes from the document object
// returns an empty string if no information can be found
func buildCVEDesciptionFromCSAFNotes(notes []*minimalCSAFNote) string {
	const seperator = " | "
	description := strings.Builder{}
	for _, note := range notes {
		if note == nil || note.Category == nil || note.Title == nil || note.Text == nil || *note.Category == string(csaf.CSAFNoteCategoryLegalDisclaimer) {
			continue
		}
		// put the strings together low level
		description.WriteString(*note.Title)
		description.WriteString(": ")
		description.WriteString(*note.Text)
		description.WriteString(seperator)
	}
	return strings.TrimSuffix(description.String(), seperator)
}

// imports csaf advisories into the db using stage + copy approach
func importCSAFAdvisories(ctx context.Context, tx pgx.Tx, advisories []models.CVE) error {
	if len(advisories) == 0 {
		return nil
	}

	advisoryRelationships := make([]models.CVERelationship, 0, len(advisories)*8)
	for i := range advisories {
		advisoryRelationships = append(advisoryRelationships, advisories[i].Relationships...)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE csaf_cves_stage (LIKE cves_stage) ON COMMIT DROP;
		CREATE TEMP TABLE csaf_cve_relationships_stage (LIKE cve_relationships_stage) ON COMMIT DROP;`); err != nil {
		return fmt.Errorf("could not create csaf staging tables: %w", err)
	}

	if err := InsertCVEsBulk(ctx, tx, advisories, "csaf_cves_stage"); err != nil {
		return fmt.Errorf("could not insert advisory cves into staging: %w", err)
	}
	if err := InsertCVERelationshipsBulk(ctx, tx, advisoryRelationships, "csaf_cve_relationships_stage"); err != nil {
		return fmt.Errorf("could not insert advisory relationships into staging: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO cves (id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector, euvd_exploit_add)
		SELECT id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector, euvd_exploit_add
		FROM csaf_cves_stage
		ON CONFLICT (id) DO NOTHING`); err != nil {
		return fmt.Errorf("could not flush advisory cves: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_relationships (target_cve, source_cve, relationship_type)
		SELECT target_cve, source_cve, relationship_type
		FROM csaf_cve_relationships_stage
		ON CONFLICT (target_cve, source_cve, relationship_type) DO NOTHING`); err != nil {
		return fmt.Errorf("could not flush advisory relationships: %w", err)
	}

	return nil
}

// arbitrary values, not yet optimized
const (
	csafFetchWorkers     = 200
	csafConverterWorkers = 2
)

// http client for rapid fire http requests to the CSAF api
var csafFetchingClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        csafFetchWorkers,
		MaxIdleConnsPerHost: csafFetchWorkers,
		MaxConnsPerHost:     csafFetchWorkers,
	},
}

// fetches and transforms CSAF advisories to CVE objects
func FetchCSAFData(ctx context.Context, baseURL string) ([]models.CVE, error) {
	start := time.Now()

	fileNames, err := fetchCSAFFileNamesFromIndex(ctx, baseURL)
	if err != nil {
		return nil, err
	}
	slog.Info("successfully read index.txt file", "entries", len(fileNames), "time", time.Since(start))
	return fetchFilesConcurrently(ctx, baseURL, fileNames)
}

// fetches all the filenames listed in the index.txt in the CSAF directory
func fetchCSAFFileNamesFromIndex(ctx context.Context, baseURL string) ([]string, error) {
	slog.Info("start reading index.txt")
	// fetch the index.txt from the base url + index path
	body, err := utils.DoGetRequestWithContext(ctx, baseURL+"index.txt", nil)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	buf, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	// file names are seperated by new line characters so string fields splits them up correctly
	fileNames := strings.Fields(string(buf))
	if len(fileNames) == 0 {
		return nil, fmt.Errorf("no files found in index.txt file")
	}
	return fileNames, err
}

// uses a worker pool + pipelining approach to fetch and convert CSAF reports concurrently
func fetchFilesConcurrently(ctx context.Context, baseURL string, fileNames []string) ([]models.CVE, error) {
	start := time.Now()

	group, ctx := errgroup.WithContext(ctx)

	fetchingJobs := make(chan string, csafFetchWorkers*1)           // files to fetch
	advisories := make(chan *minimalCSAFAdvisory, csafFetchWorkers) // CSAF reports to convert
	cveOutput := make(chan *models.CVE, batchSize)                  // final cve objects

	// push all file urls, then close the jobs channel
	group.Go(func() error {
		defer close(fetchingJobs)
		for _, fileName := range fileNames {
			select {
			case fetchingJobs <- baseURL + fileName:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	group.Go(func() error {
		fetchers, fetchCtx := errgroup.WithContext(ctx)
		for range csafFetchWorkers {
			fetchers.Go(func() error {
				return fetchCSAFReportWorker(fetchCtx, fetchingJobs, advisories, csafFetchingClient)
			})
		}
		err := fetchers.Wait()
		close(advisories)
		return err
	})

	group.Go(func() error {
		converters, convertCtx := errgroup.WithContext(ctx)
		for range csafConverterWorkers {
			converters.Go(func() error {
				return convertCSAFReportToModelsWorker(convertCtx, advisories, cveOutput)
			})
		}
		err := converters.Wait()
		close(cveOutput)
		return err
	})

	slog.Info("start fetching csaf files...")
	// collect the results on the main goroutine; the convert stage closes cveOutput
	// order depends on goroutine scheduling, so it must be sorted below for a reproducible export
	cves := make([]models.CVE, 0, len(fileNames))
	for cve := range cveOutput {
		cves = append(cves, *cve)
	}

	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("ran into error while syncing CSAF advisories, source: %s, error: %w", baseURL, err)
	}

	slices.SortFunc(cves, func(a, b models.CVE) int {
		return strings.Compare(a.CVE, b.CVE)
	})

	slog.Info("successfully finished csaf sync", "time", time.Since(start), "advisories fetched", len(cves))
	return cves, nil
}

// helper function to filter cve relations using a cves lookup map
func filterRelationshipsBySurvivingSource(relationships []models.CVERelationship, survivingCVEs map[string]struct{}) []models.CVERelationship {
	kept := relationships[:0]
	for _, relationship := range relationships {
		if _, ok := survivingCVEs[relationship.SourceCVE]; ok {
			kept = append(kept, relationship)
		}
	}
	return kept
}

// helper function to filter cvves aswell as their relationship to only surviving cves
func filterSurvivingAdvisories(advisories []models.CVE, survivingCVEs map[string]struct{}) []models.CVE {
	kept := advisories[:0]
	for _, advisory := range advisories {
		if _, ok := survivingCVEs[advisory.CVE]; !ok {
			continue
		}
		relationships := advisory.Relationships[:0]
		for _, relationship := range advisory.Relationships {
			// the referenced official cve is the source and carries the fk, so it has to survive
			if _, ok := survivingCVEs[relationship.SourceCVE]; ok {
				relationships = append(relationships, relationship)
			}
		}
		advisory.Relationships = relationships
		kept = append(kept, advisory)
	}
	return kept
}
