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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/l3montree-dev/flawfix/internal/utils"
	"github.com/pkg/errors"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type nvdService struct {
	httpClient    *http.Client
	cveRepository Repository
	leaderElector leaderElector
	configService configService
}

func newNVDService(leaderElector leaderElector, configService configService, cveRepository Repository) nvdService {
	return nvdService{
		configService: configService,
		cveRepository: cveRepository,
		leaderElector: leaderElector,

		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 3, // only allow 3 concurrent connections to the same host
			},
		},
	}
}

func (nvdService nvdService) fetchFromNVD(ctx context.Context, startIndex int) (nistResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?startIndex="+fmt.Sprint(startIndex), nil)

	if err != nil {
		return nistResponse{}, err
	}

	res, err := nvdService.httpClient.Do(req)
	if err != nil {
		return nistResponse{}, err
	}

	defer res.Body.Close()

	var resp nistResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nistResponse{}, err
	}
	return resp, nil
}

func (nvdService nvdService) initialPopulation() error {
	slog.Info("Starting initial NVD population. This is a one time process and takes a while - we have to respect the NVD API rate limits.")
	startIndex := 0
	var totalResults int
	for {
		if totalResults != 0 && startIndex >= totalResults {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := nvdService.fetchFromNVD(ctx, startIndex)
		// make sure to cancel the context
		cancel()
		if err != nil {
			return err
		}
		startIndex += resp.ResultsPerPage
		totalResults = resp.TotalResults

		slog.Info("Fetched NVD data", "datamode", "initial population", "totalResults", resp.TotalResults, "currentIndex", startIndex)

		cves := make([]CVE, len(resp.Vulnerabilities))
		for i, v := range resp.Vulnerabilities {
			cves[i] = fromNVDCVE(v.Cve)
		}

		if err := nvdService.cveRepository.SaveBatch(nil, cves); err != nil {
			return err
		}

		// check if we have more to fetch
		if resp.TotalResults > startIndex {
			// we have more to fetch
			slog.Info("There is more to fetch. Waiting for 6 seconds to respect the NVD API rate limits", "datamode", "initial population")
			time.Sleep(6 * time.Second)
		}
	}
	return nil
}

// return if there is more to fetch - and error if something went wrong
func (nvdService nvdService) fetchAfter(lastModDate time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?lastModStartDate="+lastModDate.Format(utils.ISO8601Format)+"&lastModEndDate="+time.Now().Format(utils.ISO8601Format), nil)

	if err != nil {
		return false, errors.Wrap(err, "could not create request before fetching from NVD")
	}

	res, err := nvdService.httpClient.Do(req)
	if err != nil {
		return false, errors.Wrap(err, "could not fetch from NVD")
	}

	defer res.Body.Close()

	slog.Info(baseURL + "?lastModStartDate=" + lastModDate.Format(utils.ISO8601Format) + "&lastModEndDate=" + time.Now().Format(utils.ISO8601Format))

	var resp nistResponse

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return false, errors.Wrap(err, "could not decode response from NVD")
	}

	slog.Info("Fetched NVD data", "datamode", "maintaining", "totalResults", resp.TotalResults, "resultsPerPage", resp.ResultsPerPage)
	cves := make([]CVE, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		cves[i] = fromNVDCVE(v.Cve)
	}

	// check if we have more to fetch
	if resp.TotalResults > resp.ResultsPerPage {
		// we have more to fetch
		return true, nvdService.cveRepository.SaveBatch(nil, cves)
	}

	return false, nvdService.cveRepository.SaveBatch(nil, cves)
}

// After initial data population has occurred, the last modified date parameters provide an efficient way to update a user's local repository and stay within the API rate limits. No more than once every two hours, automated requests should include a range where lastModStartDate equals the time of the last CVE or CPE received and lastModEndDate equals the current time.
// ref: https://nvd.nist.gov/developers/start-here
func (nvdService nvdService) mirror() error {
	lastModDate, err := nvdService.cveRepository.GetLastModDate()
	if err != nil {
		// we are doing the initial population
		return nvdService.initialPopulation()
	}

	moreToFetch, err := nvdService.fetchAfter(lastModDate)
	if err != nil {
		return err
	}

	if moreToFetch {
		// wait for 6 seconds to respect the NVD API rate limits
		slog.Info("maintaining nvd data. There is more to fetch. Waiting for 6 seconds to respect the NVD API rate limits", "datamode", "maintaining")
		time.Sleep(6 * time.Second)
		return nvdService.mirror()
	}

	return nil
}
