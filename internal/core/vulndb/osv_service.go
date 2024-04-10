// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"strings"
	"time"

	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/utils"
	"github.com/pkg/errors"
)

type affectedCmpRepository interface {
	SaveBatch(tx database.DB, affectedComponents []models.AffectedComponent) error
}
type osvService struct {
	httpClient            *http.Client
	affectedCmpRepository affectedCmpRepository
}

func NewOSVService(affectedCmpRepository affectedCmpRepository) osvService {
	return osvService{
		httpClient:            &http.Client{},
		affectedCmpRepository: affectedCmpRepository,
	}
}

var osvBaseURL string = "https://storage.googleapis.com/osv-vulnerabilities"

var importEcosystems = []string{
	"Go",
	"npm",
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

func (s osvService) Mirror() error {
	ecosystems, err := s.getEcosystems()
	if err != nil {
		slog.Error("could not get ecosystems", "err", err)
		return err
	}

	for _, ecosystem := range ecosystems {
		if ecosystem == "" {
			continue
		}
		// cleanup the string
		ecosystem = strings.TrimSpace(ecosystem)

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

			osv := models.OSV{}
			err = json.Unmarshal(unzippedFileBytes, &osv)
			if err != nil {
				slog.Error("could not unmarshal osv", "err", err)
				continue
			}

			if !osv.IsCVE() {
				continue
			}

			// convert the osv to affected packages
			affectedComponents := osv.GetAffectedPackages()
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
	}
	return nil
}
