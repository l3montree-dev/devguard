package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/common"
	"golang.org/x/time/rate"
)

type openSourceInsightService struct {
	httpClient  *http.Client
	rateLimiter rate.Limiter
}

func NewOpenSourceInsightService() openSourceInsightService {
	return openSourceInsightService{
		httpClient:  &http.Client{},
		rateLimiter: *rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
	}
}

var openSourceInsightsAPIURL = "https://api.deps.dev/v3"

func (s *openSourceInsightService) GetProject(ctx context.Context, projectID string) (common.OpenSourceInsightsProjectResponse, error) {
	// make sure the projectID (which is usually a github repository url) is url encoded
	projectID = url.PathEscape(projectID)

	if err := s.rateLimiter.Wait(ctx); err != nil {
		return common.OpenSourceInsightsProjectResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s", openSourceInsightsAPIURL, projectID), nil)

	if err != nil {
		return common.OpenSourceInsightsProjectResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return common.OpenSourceInsightsProjectResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return common.OpenSourceInsightsProjectResponse{}, fmt.Errorf("could not get project information: %s", res.Status)
	}

	var response common.OpenSourceInsightsProjectResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return common.OpenSourceInsightsProjectResponse{}, err
	}

	return response, nil
}

func translateEcosystem(ecosystem string) (string, error) {
	ecosystem = strings.ToLower(ecosystem)
	switch ecosystem {
	case "golang":
		return "go", nil
	case "npm":
		return "npm", nil
	case "maven":
		return "maven", nil
	case "pypi":
		return "pypi", nil
	case "nuget":
		return "nuget", nil
	case "cargo":
		return "cargo", nil
	}

	return "", fmt.Errorf("ecosystem %s is not supported", ecosystem)
}

func (s *openSourceInsightService) GetVersion(ctx context.Context, ecosystem, packageName, version string) (common.OpenSourceInsightsVersionResponse, error) {
	ecosystem, err := translateEcosystem(ecosystem)
	if err != nil {
		return common.OpenSourceInsightsVersionResponse{}, err
	}

	// replace any slashes in the package name with a colon
	if ecosystem == "maven" {
		// for maven, we need to replace the slashes with colons
		packageName = strings.ReplaceAll(packageName, "/", ":")
	}

	// make sure the package name is url encoded
	packageName = url.PathEscape(packageName)
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return common.OpenSourceInsightsVersionResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", openSourceInsightsAPIURL, ecosystem, packageName, version), nil)
	if err != nil {
		return common.OpenSourceInsightsVersionResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return common.OpenSourceInsightsVersionResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return common.OpenSourceInsightsVersionResponse{}, fmt.Errorf("could not get version information: %s", res.Status)
	}

	var response common.OpenSourceInsightsVersionResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return common.OpenSourceInsightsVersionResponse{}, err
	}

	return response, nil
}
