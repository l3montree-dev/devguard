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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/pkg/errors"
)

type osvService struct {
	httpClient            *http.Client
	affectedCmpRepository shared.AffectedComponentRepository
	cveRepository         shared.CveRepository
}

func NewOSVService(affectedCmpRepository shared.AffectedComponentRepository, cveRepository shared.CveRepository) osvService {
	return osvService{
		httpClient:            &http.Client{},
		affectedCmpRepository: affectedCmpRepository,
		cveRepository:         cveRepository,
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
	if err != nil {
		return nil, errors.Wrap(err, "could not download ecosystems")
	}
	defer res.Body.Close()

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

func (s osvService) ImportCVE(cveID string) ([]models.AffectedComponent, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID))

	if err != nil {
		return nil, errors.Wrap(err, "could not get cve")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("could not get cve")
	}

	defer resp.Body.Close()
	var osv dtos.OSV
	err = json.NewDecoder(resp.Body).Decode(&osv)

	if err != nil {
		return nil, errors.Wrap(err, "could not decode cve")
	}

	if !osv.IsCVE() {
		return nil, errors.New("not a cve")
	}

	affectedComponents := models.AffectedComponentsFromOSV(&osv)

	err = s.affectedCmpRepository.SaveBatch(nil, affectedComponents)
	if err != nil {
		return nil, errors.Wrap(err, "could not save affected packages")
	}

	return affectedComponents, nil
}

var waitGroup sync.WaitGroup = sync.WaitGroup{}

const numOfGoRoutines int = 10

func (s osvService) Mirror() error {
	zips := make(chan *zip.Reader, 2)
	jobs := make(chan *zip.File, numOfGoRoutines*20)

	go s.workerZipFunction(zips)

	for i := range numOfGoRoutines {
		go s.workerFileFunction(i+1, jobs)
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

func (s osvService) workerZipFunction(results chan<- *zip.Reader) {
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
		err := s.affectedCmpRepository.DeleteAll(nil, ecosystem)
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

func (s osvService) workerFileFunction(id int, jobs <-chan *zip.File) {
	waitGroup.Add(1)
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
		tx := s.cveRepository.Begin()

		newCVE := OSVToCVE(&osv)

		err = s.cveRepository.CreateCVEWithConflictHandling(tx, &newCVE)
		if err != nil {
			slog.Error("could not save CVE", "CVE", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}

		affectedComponents := models.AffectedComponentsFromOSV(&osv)

		// then create the affected components
		err = s.affectedCmpRepository.CreateAffectedComponentsUsingUnnest(tx, affectedComponents)
		if err != nil {
			slog.Error("could not save affected components", "cve", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}

		err = s.cveRepository.CreateCVEAffectedComponentsEntries(tx, &newCVE, affectedComponents)
		if err != nil {
			slog.Error("could not save to cve_affected_components relation table", "cve", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}
		tx.Commit()
	}
	waitGroup.Done()
}

func OSVToCVE(osv *dtos.OSV) models.CVE {
	cve := models.CVE{}
	cvssScore, cvssVector, ok := hasValidCVSSScore(osv)
	if ok {
		cve.CVSS = float32(cvssScore)
		cve.Vector = cvssVector
	} else {
		// if we cannot parse a CVSS score we save the CVE with a CVSS score of -1
		cve.CVSS = float32(-1)
	}

	if !strings.HasPrefix(osv.ID, "CVE-") {
		// if its not a CVE itself we need want to add additional information about related CVEs
		associatedCVEs := osv.GetAssociatedCVEs()
		// clean up statistics by removing entries with no associations
		if len(associatedCVEs) > 0 {
			cve.References = strings.Join(associatedCVEs, ",")
		}
	}

	cve.CVE = osv.ID
	cve.Description = osv.Summary

	return cve
}

// checks if a valid CVSS score is available, if so return the score as well as the corresponding vector
func hasValidCVSSScore(osv *dtos.OSV) (float64, string, bool) {
	for _, severity := range osv.Severity {
		// currently only supporting CVSS Version 3
		switch severity.Type {
		case "CVSS_V3":
			cvssScore, err := gocvss30.ParseVector(severity.Score)
			if err == nil {
				return cvssScore.BaseScore(), cvssScore.Vector(), true
			}
		case "CVSS_V4":
			cvssScore, err := gocvss40.ParseVector(severity.Score)
			if err == nil {
				return cvssScore.Score(), cvssScore.Vector(), true
			}
		default:
			// Debug purpose can be deleted in deployment
			slog.Info("We do not support severity type: %s with Score: %s", severity.Type, severity.Score)
		}
	}
	return 0, "", false
}

func shouldIgnoreVulnerabilityID(id string) bool {
	prefix, _, ok := strings.Cut(id, "-")
	if !ok {
		// false negatives are ok
		return true
	}
	return slices.Contains(ignoreVulnerabilityEcosystems, prefix)
}
