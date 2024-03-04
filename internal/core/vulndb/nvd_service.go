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
	"net/url"
	"sync"
	"time"

	"github.com/l3montree-dev/flawfix/internal/utils"
	"github.com/pkg/errors"
)

var baseURL = url.URL{
	Scheme: "https",
	Host:   "services.nvd.nist.gov",
	Path:   "/rest/json/cves/2.0",
}

type NVDService struct {
	httpClient    *http.Client
	cveRepository Repository
	leaderElector leaderElector
	configService configService
	lock          *sync.Mutex
}

func NewNVDService(leaderElector leaderElector, configService configService, cveRepository Repository) NVDService {
	return NVDService{
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

func (nvdService NVDService) ImportCVE(cveID string) (CVE, error) {
	// make a copy of the base url
	u := baseURL
	q := u.Query()
	q.Add("cveId", cveID)
	u.RawQuery = q.Encode()

	resp, err := nvdService.fetchJSONFromNVD(u, 1)
	if err != nil {
		slog.Error("Could not fetch from NVD", "err", err)
		return CVE{}, err
	}

	if len(resp.Vulnerabilities) == 0 {
		return CVE{}, fmt.Errorf("could not find CVE with id %s", cveID)
	}

	cve := fromNVDCVE(resp.Vulnerabilities[0].Cve)
	if err := nvdService.cveRepository.Save(nil, &cve); err != nil {
		return CVE{}, err
	}

	return cve, nil
}

// this method will retry 3 times before returning an error
func (nvdService NVDService) fetchJSONFromNVD(url url.URL, currentTry int) (nistResponse, error) {
	// limit to a single request all 6 seconds max
	nvdService.lock.Lock()
	time.AfterFunc(6*time.Second, func() {
		nvdService.lock.Unlock()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)

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

func (nvdService NVDService) saveResponseInDB(resp nistResponse) error {
	cves := make([]CVE, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		cves[i] = fromNVDCVE(v.Cve)
	}

	return nvdService.cveRepository.SaveBatch(nil, cves)
}

func (nvdService NVDService) initialPopulation() error {
	slog.Info("starting initial NVD population. This is a one time process and takes a while - we have to respect the NVD API rate limits.")

	return nvdService.fetchAndSaveAllPages(baseURL)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (nvdService NVDService) fetchAndSaveAllPages(url url.URL) error {
	u := url

	startIndex := 0
	var totalResults int

	for {
		if totalResults != 0 && startIndex >= totalResults {
			break
		}
		start := time.Now()

		q := u.Query()
		q.Set("startIndex", fmt.Sprint(startIndex))
		u.RawQuery = q.Encode()

		slog.Info("fetching all pages from nvd", "url", u.String())
		resp, err := nvdService.fetchJSONFromNVD(u, 1)
		// make sure to cancel the context
		apiRequestFinished := time.Now()
		if err != nil {
			return err
		}
		startIndex += resp.ResultsPerPage
		totalResults = resp.TotalResults

		slog.Info("fetched NVD data", "totalResults", resp.TotalResults, "currentIndex", startIndex)

		if err := nvdService.saveResponseInDB(resp); err != nil {
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

// return if there is more to fetch - and error if something went wrong
func (nvdService NVDService) fetchAfter(lastModDate time.Time) error {
	slog.Info("starting to maintain NVD data", "lastModDate", lastModDate.String())
	now := time.Now()
	// we can only fetch 120 days at a time
	// we use 119 days, to make sure, that nvd is happy with the date range
	endDate := minTime(now, lastModDate.Add(119*24*time.Hour))
	for lastModDate.Before(now) {
		u := baseURL
		q := u.Query()
		q.Add("lastModStartDate", lastModDate.Format(utils.ISO8601Format))
		q.Add("lastModEndDate", endDate.Format(utils.ISO8601Format))
		u.RawQuery = q.Encode()

		if err := nvdService.fetchAndSaveAllPages(u); err != nil {
			return err
		}

		// update the range
		lastModDate = endDate
		endDate = minTime(now, endDate.Add(119*24*time.Hour))
	}
	return nil
}

// After initial data population has occurred, the last modified date parameters provide an efficient way to update a user's local repository and stay within the API rate limits. No more than once every two hours, automated requests should include a range where lastModStartDate equals the time of the last CVE or CPE received and lastModEndDate equals the current time.
// ref: https://nvd.nist.gov/developers/start-here
func (nvdService NVDService) mirror() error {
	lastModDate, err := nvdService.cveRepository.GetLastModDate()
	if err != nil {
		// we are doing the initial population
		return nvdService.initialPopulation()
	}

	return nvdService.fetchAfter(lastModDate)
}
