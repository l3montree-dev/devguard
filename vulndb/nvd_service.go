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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
	"gorm.io/datatypes"
)

var baseURL = url.URL{
	Scheme: "https",
	Host:   "services.nvd.nist.gov",
	Path:   "/rest/json/cves/2.0",
}

// this is the first cve starting from 2016
const nvdStartIndex = 74684

type NVDService struct {
	httpClient    *http.Client
	cveRepository shared.CveRepository
	lock          *sync.Mutex
}

func NewNVDService(cveRepository shared.CveRepository) NVDService {
	return NVDService{
		cveRepository: cveRepository,
		lock:          &sync.Mutex{},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 3, // only allow 3 concurrent connections to the same host
			},
		},
	}
}

func (nvdService NVDService) ImportCVE(cveID string) (models.CVE, error) {
	// make a copy of the base url
	u := baseURL
	q := u.Query()
	q.Add("cveID", cveID)
	u.RawQuery = q.Encode()

	resp, err := nvdService.fetchJSONFromNVD(u, 1)
	if err != nil {
		slog.Error("Could not fetch from NVD", "err", err)
		return models.CVE{}, err
	}

	if len(resp.Vulnerabilities) == 0 {
		return models.CVE{}, fmt.Errorf("could not find CVE with id %s", cveID)
	}

	var cve models.CVE
	var weaknesses []models.Weakness

	err = nvdService.cveRepository.Transaction(func(tx shared.DB) error {
		cve, weaknesses = fromNVDCVE(resp.Vulnerabilities[0].Cve)
		if err := nvdService.cveRepository.Save(tx, &cve); err != nil {
			return err
		}
		if err := nvdService.cveRepository.GetDB(tx).Model(&cve).Association("Weaknesses").Append(weaknesses); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return models.CVE{}, err
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
	cves := make([]models.CVE, len(resp.Vulnerabilities))
	weaknesses := make([][]models.Weakness, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		cves[i], weaknesses[i] = fromNVDCVE(v.Cve)
	}

	for i, cve := range cves {
		tmp := cve
		err := nvdService.cveRepository.Transaction(func(tx shared.DB) error {
			if err := nvdService.cveRepository.Save(tx, &tmp); err != nil {
				slog.Warn("Could not save CVE", "err", err)
				return err
			}
			// save the weaknesses
			if err := nvdService.cveRepository.GetDB(tx).Model(&tmp).Association("Weaknesses").Append(weaknesses[i]); err != nil {
				slog.Warn("Could not save weaknesses", "err", err)
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (nvdService NVDService) InitialPopulation() error {
	slog.Info("starting initial NVD population. This is a one time process and takes a while - we have to respect the NVD API rate limits.")

	return nvdService.fetchAndSaveAllPages(baseURL, nvdStartIndex)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (nvdService NVDService) fetchAndSaveAllPages(url url.URL, startIndex int) error {
	u := url

	totalResults := -1

	for totalResults == -1 || startIndex < totalResults {

		start := time.Now()

		q := u.Query()
		q.Set("startIndex", fmt.Sprint(startIndex))
		u.RawQuery = q.Encode()

		slog.Info("fetching all pages from nvd", "url", u.String())
		resp, err := nvdService.fetchJSONFromNVD(u, 1)

		apiRequestFinished := time.Now()
		if err != nil {
			return err
		}
		startIndex += resp.ResultsPerPage
		totalResults = resp.TotalResults

		slog.Info("fetched NVD data", "totalResults", resp.TotalResults, "currentIndex", startIndex)

		if err := nvdService.saveResponseInDB(resp); err != nil {
			slog.Warn("Could not save response in DB", "err", err)
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

func (nvdService NVDService) FetchAfterIndex(index int) error {
	slog.Info("starting NVD population after index. This takes a while - we have to respect the NVD API rate limits.", "index", index)
	return nvdService.fetchAndSaveAllPages(baseURL, index)
}

func (nvdService NVDService) FetchAfter(lastModDate time.Time) error {
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

		if err := nvdService.fetchAndSaveAllPages(u, 0); err != nil {
			return err
		}

		// update the range
		lastModDate = endDate
		endDate = minTime(now, endDate.Add(119*24*time.Hour))
	}
	return nil
}

func (nvdService NVDService) Sync() error {
	lastModDate, err := nvdService.cveRepository.GetLastModDate()
	if err != nil {
		// we are doing the initial population
		return nvdService.InitialPopulation()
	}

	return nvdService.FetchAfter(lastModDate)
}

type cvssMetric struct {
	Severity              string
	CVSS                  float32
	ExploitabilityScore   float32
	ImpactScore           float32
	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	Vector                string
}

func toDate(date *utils.Date) *datatypes.Date {
	if date == nil {
		return nil
	}
	t := datatypes.Date(*date)
	return &t
}

func getCVSSMetric(nvdCVE nvdCVE) cvssMetric {
	if len(nvdCVE.Metrics.CvssMetricV40) > 0 {
		v40 := nvdCVE.Metrics.CvssMetricV40[0].CvssData
		return cvssMetric{
			Severity:              v40.BaseSeverity,
			CVSS:                  float32(v40.BaseScore),
			ExploitabilityScore:   0, // CVSS v4.0 doesn't provide separate exploitability score
			ImpactScore:           0, // CVSS v4.0 doesn't provide separate impact score
			AttackVector:          v40.AttackVector,
			AttackComplexity:      v40.AttackComplexity,
			PrivilegesRequired:    v40.PrivilegesRequired,
			UserInteraction:       v40.UserInteraction,
			Scope:                 "", // CVSS v4.0 doesn't have a scope field
			ConfidentialityImpact: v40.VulnConfidentialityImpact,
			IntegrityImpact:       v40.VulnIntegrityImpact,
			AvailabilityImpact:    v40.VulnAvailabilityImpact,
			Vector:                v40.VectorString,
		}
	}
	// check if cvss v3 is available
	if len(nvdCVE.Metrics.CvssMetricV31) > 0 {
		return cvssMetric{
			Severity:              nvdCVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity,
			CVSS:                  float32(nvdCVE.Metrics.CvssMetricV31[0].CvssData.BaseScore),
			ExploitabilityScore:   float32(nvdCVE.Metrics.CvssMetricV31[0].ExploitabilityScore),
			ImpactScore:           float32(nvdCVE.Metrics.CvssMetricV31[0].ImpactScore),
			AttackVector:          nvdCVE.Metrics.CvssMetricV31[0].CvssData.AttackVector,
			AttackComplexity:      nvdCVE.Metrics.CvssMetricV31[0].CvssData.AttackComplexity,
			PrivilegesRequired:    nvdCVE.Metrics.CvssMetricV31[0].CvssData.PrivilegesRequired,
			UserInteraction:       nvdCVE.Metrics.CvssMetricV31[0].CvssData.UserInteraction,
			Scope:                 nvdCVE.Metrics.CvssMetricV31[0].CvssData.Scope,
			ConfidentialityImpact: nvdCVE.Metrics.CvssMetricV31[0].CvssData.ConfidentialityImpact,
			IntegrityImpact:       nvdCVE.Metrics.CvssMetricV31[0].CvssData.IntegrityImpact,
			AvailabilityImpact:    nvdCVE.Metrics.CvssMetricV31[0].CvssData.AvailabilityImpact,
			Vector:                nvdCVE.Metrics.CvssMetricV31[0].CvssData.VectorString,
		}
	}
	if len(nvdCVE.Metrics.CvssMetricV2) == 0 {
		return cvssMetric{}
	}

	return cvssMetric{
		Severity:              nvdCVE.Metrics.CvssMetricV2[0].BaseSeverity,
		CVSS:                  float32(nvdCVE.Metrics.CvssMetricV2[0].CvssData.BaseScore),
		ExploitabilityScore:   float32(nvdCVE.Metrics.CvssMetricV2[0].ExploitabilityScore),
		ImpactScore:           float32(nvdCVE.Metrics.CvssMetricV2[0].ImpactScore),
		AttackVector:          nvdCVE.Metrics.CvssMetricV2[0].CvssData.AccessVector,
		AttackComplexity:      nvdCVE.Metrics.CvssMetricV2[0].CvssData.AccessComplexity,
		PrivilegesRequired:    nvdCVE.Metrics.CvssMetricV2[0].CvssData.Authentication,
		UserInteraction:       "",
		Scope:                 "",
		ConfidentialityImpact: nvdCVE.Metrics.CvssMetricV2[0].CvssData.ConfidentialityImpact,
		IntegrityImpact:       nvdCVE.Metrics.CvssMetricV2[0].CvssData.IntegrityImpact,
		AvailabilityImpact:    nvdCVE.Metrics.CvssMetricV2[0].CvssData.AvailabilityImpact,
		Vector:                nvdCVE.Metrics.CvssMetricV2[0].CvssData.VectorString,
	}
}

func fromNVDCVE(nistCVE nvdCVE) (models.CVE, []models.Weakness) {
	published, err := time.Parse(utils.ISO8601Format, nistCVE.Published)
	if err != nil {
		published = time.Now()
	}

	lastModified, err := time.Parse(utils.ISO8601Format, nistCVE.LastModified)
	if err != nil {
		slog.Error("Error while parsing last modified date", "err", err)
		lastModified = time.Now()
	}

	description := ""

	for _, d := range nistCVE.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}

	// build the cwe list
	weaknesses := []models.Weakness{}

	for _, w := range nistCVE.Weaknesses {
		for _, d := range w.Description {
			if !strings.HasPrefix(d.Value, "CWE-") {
				// only handle CWES - just continue. The nist might give us other weaknesses
				continue
			}

			if d.Lang == "en" {
				weaknesses = append(weaknesses, models.Weakness{
					Source: w.Source,
					Type:   w.Type,
					CWEID:  d.Value,
					CVEID:  nistCVE.ID,
				})
			}
		}
	}

	cvssMetric := getCVSSMetric(nistCVE)

	// marshal the references
	refs, err := json.Marshal(nistCVE.References)
	if err != nil {
		slog.Error("Error while marshaling references", "err", err)
	}

	return models.CVE{
		CVE:              nistCVE.ID,
		DatePublished:    published,
		DateLastModified: lastModified,

		Description: description,

		CVSS: cvssMetric.CVSS,

		CISAExploitAdd:        toDate(nistCVE.CISAExploitAdd),
		CISAActionDue:         toDate(nistCVE.CISAActionDue),
		CISARequiredAction:    nistCVE.CISARequiredAction,
		CISAVulnerabilityName: nistCVE.CISAVulnerabilityName,

		Vector: cvssMetric.Vector,

		References: string(refs),
	}, weaknesses

}
