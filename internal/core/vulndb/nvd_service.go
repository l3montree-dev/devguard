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
	"sync"
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
	lock          *sync.Mutex
}

func newNVDService(leaderElector leaderElector, configService configService, cveRepository Repository) nvdService {
	return nvdService{
		configService: configService,
		cveRepository: cveRepository,
		leaderElector: leaderElector,
		lock:          &sync.Mutex{},

		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 3, // only allow 3 concurrent connections to the same host
			},
		},
	}
}

// this method will retry 3 times before returning an error
func (nvdService nvdService) fetchJSONFromNVD(url string, currentTry int) (nistResponse, error) {
	// limit to a single request all 6 seconds max
	nvdService.lock.Lock()
	time.AfterFunc(6*time.Second, func() {
		nvdService.lock.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return nistResponse{}, errors.Wrap(err, "could not create request before fetching from NVD")
	}

	res, err := nvdService.httpClient.Do(req)
	if err != nil {
		// check if we should retry
		if currentTry < 10 {
			slog.Error("Could not fetch from NVD", "try", currentTry, "err", err)
			return nvdService.fetchJSONFromNVD(url, currentTry+1)
		}
	}
	if res.StatusCode != http.StatusOK {
		if currentTry < 10 {
			slog.Error("Could not fetch from NVD", "try", currentTry, "statusCode", res.StatusCode)
			return nvdService.fetchJSONFromNVD(url, currentTry+1)
		}
		return nistResponse{}, fmt.Errorf("could not fetch from NVD. Status code: %d", res.StatusCode)
	}

	defer res.Body.Close()

	var resp nistResponse

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		slog.Error("Could not decode response from NVD", "err", err)
		// check if we should retry
		if currentTry < 10 {
			slog.Info("Could not fetch from NVD. Retrying in 6 seconds", "try", currentTry)
			return nvdService.fetchJSONFromNVD(url, currentTry+1)
		}
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
		start := time.Now()

		resp, err := nvdService.fetchJSONFromNVD(baseURL+"?startIndex="+fmt.Sprint(startIndex), 1)
		// make sure to cancel the context
		apiRequestFinished := time.Now()
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

		slog.Info("Done iteration", "apiRequestTime", apiRequestFinished.Sub(start).String(), "databaseTime", time.Since(apiRequestFinished).String())

		// check if we have more to fetch
		if resp.TotalResults > startIndex {
			// we have more to fetch
			slog.Info("There is more to fetch...")
		}
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// return if there is more to fetch - and error if something went wrong
func (nvdService nvdService) fetchAfter(lastModDate time.Time) (bool, error) {
	currentTime := time.Now()
	endDate := minTime(currentTime, lastModDate.Add(119*24*time.Hour))

	resp, err := nvdService.fetchJSONFromNVD(baseURL+"?lastModStartDate="+lastModDate.Format(utils.ISO8601Format)+"&lastModEndDate="+endDate.Format(utils.ISO8601Format), 1)
	if err != nil {
		return false, err
	}

	slog.Info("Fetched NVD data", "datamode", "maintaining", "totalResults", resp.TotalResults, "resultsPerPage", resp.ResultsPerPage)

	cves := make([]CVE, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		cves[i] = fromNVDCVE(v.Cve)
	}

	return resp.TotalResults > resp.ResultsPerPage || endDate.Before(currentTime), nvdService.cveRepository.SaveBatch(nil, cves)
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
		return nvdService.mirror()
	}

	return nil
}
