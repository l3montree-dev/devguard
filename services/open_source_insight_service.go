package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/time/rate"
)

type openSourceInsightService struct {
	httpClient  *http.Client
	rateLimiter rate.Limiter
}

var _ shared.OpenSourceInsightService = (*openSourceInsightService)(nil) // Ensure openSourceInsightService implements shared.OpenSourceInsightService interface

func NewOpenSourceInsightService() *openSourceInsightService {
	return &openSourceInsightService{
		httpClient:  &http.Client{Transport: utils.EgressTransport},
		rateLimiter: *rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
	}
}

var openSourceInsightsAPIURL = "https://api.deps.dev/v3"

func (s *openSourceInsightService) GetProject(ctx context.Context, projectID string) (dtos.OpenSourceInsightsProjectResponse, error) {
	// make sure the projectID (which is usually a github repository url) is url encoded
	projectID = url.PathEscape(projectID)

	if err := s.rateLimiter.Wait(ctx); err != nil {
		return dtos.OpenSourceInsightsProjectResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s", openSourceInsightsAPIURL, projectID), nil)

	if err != nil {
		return dtos.OpenSourceInsightsProjectResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return dtos.OpenSourceInsightsProjectResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return dtos.OpenSourceInsightsProjectResponse{}, fmt.Errorf("could not get project information: %s", res.Status)
	}

	var response dtos.OpenSourceInsightsProjectResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return dtos.OpenSourceInsightsProjectResponse{}, err
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

func (s *openSourceInsightService) GetVersion(ctx context.Context, ecosystem, packageName, version string) (dtos.OpenSourceInsightsVersionResponse, error) {
	ecosystem, err := translateEcosystem(ecosystem)
	if err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, err
	}

	// replace any slashes in the package name with a colon
	if ecosystem == "maven" {
		// for maven, we need to replace the slashes with colons
		packageName = strings.ReplaceAll(packageName, "/", ":")
	}

	if ecosystem == "go" && version != "" {
		return s.getGoVersion(ctx, ecosystem, packageName, version)
	}

	return s.getVersion(ctx, ecosystem, packageName, version)
}

func (s *openSourceInsightService) getGoVersion(ctx context.Context, ecosystem, packageName, version string) (dtos.OpenSourceInsightsVersionResponse, error) {
	preferredVersion := version
	fallbackVersion := strings.TrimPrefix(version, "v")
	if !strings.HasPrefix(version, "v") {
		preferredVersion = "v" + version
		fallbackVersion = version
	}

	response, err := s.getVersion(ctx, ecosystem, packageName, preferredVersion)
	if err == nil || fallbackVersion == preferredVersion {
		return response, err
	}

	return s.getVersion(ctx, ecosystem, packageName, fallbackVersion)
}

func (s *openSourceInsightService) getVersion(ctx context.Context, ecosystem, packageName, version string) (dtos.OpenSourceInsightsVersionResponse, error) {
	// make sure the package name is url encoded
	packageName = url.PathEscape(packageName)
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", openSourceInsightsAPIURL, ecosystem, packageName, version), nil)
	if err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("could not get version information: %s", res.Status)
	}

	var response dtos.OpenSourceInsightsVersionResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, err
	}

	return response, nil
}
