package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

var ErrNotCVE = fmt.Errorf("not a CVE")

type Service interface {
	IsCVE(ruleID string) bool
	GetCVE(ctx context.Context, ruleID string) (CVEModel, error)
}

type service struct {
	repository Repository
	httpClient *http.Client
}

func NewService(repository Repository) Service {
	return &service{
		repository: repository,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 3, // only allow 3 concurrent connections to the same host
			},
		},
	}
}

func (s service) IsCVE(ruleID string) bool {
	return ruleID[:3] == "CVE"
}

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

func (s service) fetchCVE(ctx context.Context, ruleID string) (CVEModel, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?cveId="+ruleID, nil)
	if err != nil {
		return CVEModel{}, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return CVEModel{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CVEModel{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var nistResp NISTResponse
	err = json.NewDecoder(resp.Body).Decode(&nistResp)
	if err != nil {
		return CVEModel{}, err
	}

	if len(nistResp.Vulnerabilities) == 0 {
		return CVEModel{}, fmt.Errorf("no vulnerabilities found")
	}

	return nistResp.ToModel(), nil
}

func (s service) GetCVE(ctx context.Context, ruleID string) (CVEModel, error) {
	if !s.IsCVE(ruleID) {
		return CVEModel{}, ErrNotCVE
	}

	// check if the CVE does already exist
	cve, err := s.repository.FindByID(ruleID)
	if err != nil {
		// it does not yet exist - check if we can fetch information from an external source
		fetchedCVE, err := s.fetchCVE(ctx, ruleID)
		if err != nil {
			return CVEModel{}, err
		}

		// create the CVE
		err = s.repository.Create(nil, &fetchedCVE)
		if err != nil {
			return CVEModel{}, err
		}

		return fetchedCVE, nil
	}

	return cve, nil
}
