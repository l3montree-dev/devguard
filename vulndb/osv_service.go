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
	// "AlmaLinux",
	"Alpine",
	// "Android",
	"Bitnami",
	"Chainguard",
	// "CRAN",
	"crates.io",
	"Debian",
	"GIT",
	"Github Actions",
	// "Hackage",
	// "Hex",
	"Linux",
	"Maven",
	"NuGet",
	// "OSS-Fuzz",
	"Packagist",
	// "Pub",
	"PyPI",
	// "Rocky Linux",
	"RubyGems",
	// "SwiftURL",
	// "Ubuntu",
	// "Wolfi",
	"Red Hat",
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
	for i, e := range ecosystems {
		ecosystems[i] = strings.TrimSpace(e)
	}

	// filter out the ecosystems we are interested in
	ecosystems = utils.Filter(ecosystems, func(s string) bool {
		for _, e := range importEcosystems {
			if s == e {
				return true
			}
		}
		return false
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

	affectedComponents := models.AffectedComponentFromOSV(osv)

	err = s.affectedCmpRepository.SaveBatch(nil, affectedComponents)
	if err != nil {
		return nil, errors.Wrap(err, "could not save affected packages")
	}

	return affectedComponents, nil
}

func (s osvService) Mirror() error {
	ecosystems, err := s.getEcosystems()
	if err != nil {
		slog.Error("could not get ecosystems", "err", err)
		return err
	}
	wg := sync.WaitGroup{}

	for _, ecosystem := range ecosystems {
		if ecosystem == "" {
			continue
		}

		wg.Add(1)
		go func(ecosystem string) {
			defer wg.Done()
			slog.Info("importing ecosystem", "ecosystem", ecosystem)
			start := time.Now()
			// remove all affected packages for this ecosystem
			err := s.affectedCmpRepository.DeleteAll(nil, ecosystem)
			if err != nil {
				slog.Error("could not delete affected packages", "err", err)
				return
			}
			slog.Info("deleted all affected packages", "ecosystem", ecosystem, "duration", time.Since(start))

			// cleanup the string
			ecosystem = strings.TrimSpace(ecosystem)

			// download the zip and extract it in memory
			zipReader, err := s.getOSVZipContainingEcosystem(ecosystem)

			if err != nil {
				slog.Error("could not read zip", "err", err)
				return
			}

			if len(zipReader.File) == 0 {
				slog.Error("no files found in zip")
				return
			}

			totalPackagesSaved := 0
			packageErrors := 0
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

				newCVE, err := OSVToCVE(osv)
				// swallow error so we can still create affected components
				if err == nil {
					err = s.cveRepository.Save(nil, &newCVE)
					if err != nil {
						// swallow error so we can still create affected components
						slog.Error("could not save CVE to db")
					}
				}

				// convert the osv to affected packages
				affectedComponents := models.AffectedComponentFromOSV(osv)
				// save the affected packages
				err = s.affectedCmpRepository.SaveBatch(nil, affectedComponents)
				if err != nil {
					packageErrors += len(affectedComponents)
					slog.Error("could not save affected packages", "err", err, "file", file.Name, "ecosystem", ecosystem)
					continue
				} else {
					totalPackagesSaved += len(affectedComponents)
				}
			}
			// add the affected packages to the list
			slog.Info("saved affected packages", "ecosystem", ecosystem, "total", totalPackagesSaved, "errors", packageErrors)
		}(ecosystem)
	}
	wg.Wait()
	return nil
}

var osvWithMissingCVSSScores int
var totalAmountOfAssociations int
var numberOfIterations int

func OSVToCVE(osv dtos.OSV) (models.CVE, error) {
	cve := models.CVE{}

	cvssScore, cvssVector, ok := hasValidCVSSScore(osv)
	if !ok {
		// if we cannot parse a CVSS score we are currently not saving the CVE
		osvWithMissingCVSSScores++
		if osvWithMissingCVSSScores%30000 == 0 {
			slog.Warn("CVSS Error", "total errors", osvWithMissingCVSSScores)
		}
		return cve, fmt.Errorf("could not parse CVSS Score")
	}

	if !strings.HasPrefix(osv.ID, "CVE-") {
		// if its not a CVE itself we need want to add additional information about related CVEs
		associatedCVEs := osv.GetCVE()
		// clean up statistics by removing entries with no associations
		if len(associatedCVEs) > 0 {
			totalAmountOfAssociations += len(associatedCVEs)
			numberOfIterations++
			if numberOfIterations%700 == 0 {
				avg := float32(totalAmountOfAssociations) / float32(numberOfIterations)
				slog.Info("Current average", "avg", avg)
			}
			cve.References = strings.Join(associatedCVEs, ",")
		}
	}

	cve.CVSS = float32(cvssScore)
	cve.Vector = cvssVector

	cve.CVE = osv.ID
	cve.Description = osv.Summary

	return cve, nil
}

// checks if a valid CVSS score is available, if so return the score as well as the corresponding vector
func hasValidCVSSScore(osv dtos.OSV) (float64, string, bool) {
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
