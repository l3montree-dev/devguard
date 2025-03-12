package vulndb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type DepsDevVersionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt  time.Time `json:"publishedAt"`
	IsDefault    bool      `json:"isDefault"`
	Licenses     []string  `json:"licenses"`
	AdvisoryKeys []any     `json:"advisoryKeys"`
	Links        []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	SlsaProvenances []any    `json:"slsaProvenances"`
	Attestations    []any    `json:"attestations"`
	Registries      []string `json:"registries"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationProvenance string `json:"relationProvenance"`
		RelationType       string `json:"relationType"`
	} `json:"relatedProjects"`
}

type DepsDevProjectResponse struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	OpenIssuesCount int    `json:"openIssuesCount"`
	StarsCount      int    `json:"starsCount"`
	ForksCount      int    `json:"forksCount"`
	License         string `json:"license"`
	Description     string `json:"description"`
	Homepage        string `json:"homepage"`
	Scorecard       struct {
		Date       time.Time `json:"date"`
		Repository struct {
			Name   string `json:"name"`
			Commit string `json:"commit"`
		} `json:"repository"`
		Scorecard struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		} `json:"scorecard"`
		Checks []struct {
			Name          string `json:"name"`
			Documentation struct {
				ShortDescription string `json:"shortDescription"`
				URL              string `json:"url"`
			} `json:"documentation"`
			Score   int    `json:"score"`
			Reason  string `json:"reason"`
			Details []any  `json:"details"`
		} `json:"checks"`
		OverallScore float64 `json:"overallScore"`
		Metadata     []any   `json:"metadata"`
	} `json:"scorecard"`
}

type depsDevService struct {
	httpClient *http.Client
}

func NewDepsDevService() depsDevService {
	return depsDevService{
		httpClient: &http.Client{},
	}
}

var depsDevApiURL = "https://api.deps.dev/v3"

func (s *depsDevService) GetProject(projectID string) (DepsDevProjectResponse, error) {
	// make sure the projectID (which is usually a github repository url) is url encoded
	projectID = url.PathEscape(projectID)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s", depsDevApiURL, projectID), nil)
	if err != nil {
		return DepsDevProjectResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return DepsDevProjectResponse{}, err
	}

	var response DepsDevProjectResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return DepsDevProjectResponse{}, err
	}

	return response, nil
}

func (s *depsDevService) GetVersion(ecosystem, packageName, version string) (DepsDevVersionResponse, error) {
	// make sure the package name is url encoded
	packageName = url.PathEscape(packageName)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", depsDevApiURL, ecosystem, packageName, version), nil)
	if err != nil {
		return DepsDevVersionResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return DepsDevVersionResponse{}, err
	}

	var response DepsDevVersionResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return DepsDevVersionResponse{}, err
	}

	return response, nil
}
