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
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

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
}

func NewOSVService(affectedCmpRepository shared.AffectedComponentRepository, cveRepository shared.CveRepository, cveRelationshipRepository shared.CVERelationshipRepository) osvService {
	return osvService{
		httpClient:                &http.Client{},
		affectedCmpRepository:     affectedCmpRepository,
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
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

const numOfGoRoutines int = 10

func (s osvService) Mirror() error {
	zips := make(chan *zip.Reader, 2)
	jobs := make(chan *zip.File, numOfGoRoutines*20)

	waitGroup := &sync.WaitGroup{}

	go s.workerZipFunction(zips)

	for range numOfGoRoutines {
		waitGroup.Add(1)
		go s.workerFileFunction(waitGroup, jobs)
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

func (s osvService) workerFileFunction(waitGroup *sync.WaitGroup, jobs <-chan *zip.File) {
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

		newCVE := transformer.OSVToCVE(&osv)

		err = s.cveRepository.CreateCVEWithConflictHandling(tx, &newCVE)
		if err != nil {
			slog.Error("could not save CVE", "CVE", newCVE.CVE, "error", err)
			tx.Rollback()
			continue
		}

		relations := transformer.OSVToCVERelationships(&osv)

		err = s.cveRelationshipRepository.SaveBatch(tx, relations)
		if err != nil {
			slog.Error("could not save cve relation", "error", err)
			tx.Rollback()
			continue
		}

		affectedComponents := transformer.AffectedComponentsFromOSV(&osv)

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
			tx := s.cveRepository.Begin()

			relations := transformer.OSVToCVERelationships(&osv)

			err = s.cveRelationshipRepository.SaveBatch(tx, relations)
			if err != nil {
				slog.Error("could not save cve relation", "error", err)
				tx.Rollback()
				continue
			}

			newCVE := transformer.OSVToCVE(&osv)

			err = s.cveRepository.CreateCVEWithConflictHandling(tx, &newCVE)
			if err != nil {
				slog.Error("could not save CVE", "CVE", newCVE.CVE, "error", err)
				tx.Rollback()
				continue
			}

			affectedComponents := transformer.AffectedComponentsFromOSV(&osv)

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

	}
	return nil
}
