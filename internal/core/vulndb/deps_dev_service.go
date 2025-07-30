package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"golang.org/x/time/rate"
)

type depsDevService struct {
	httpClient  *http.Client
	rateLimiter rate.Limiter
}

func NewDepsDevService() depsDevService {
	return depsDevService{
		httpClient:  &http.Client{},
		rateLimiter: *rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
	}
}

var depsDevAPIURL = "https://api.deps.dev/v3"

func (s *depsDevService) GetProject(ctx context.Context, projectID string) (common.DepsDevProjectResponse, error) {
	// make sure the projectID (which is usually a github repository url) is url encoded
	projectID = url.PathEscape(projectID)

	if err := s.rateLimiter.Wait(ctx); err != nil {
		return common.DepsDevProjectResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects/%s", depsDevAPIURL, projectID), nil)

	if err != nil {
		return common.DepsDevProjectResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return common.DepsDevProjectResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return common.DepsDevProjectResponse{}, fmt.Errorf("could not get project information: %s", res.Status)
	}

	var response common.DepsDevProjectResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return common.DepsDevProjectResponse{}, err
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

func (s *depsDevService) GetVersion(ctx context.Context, ecosystem, packageName, version string) (common.DepsDevVersionResponse, error) {
	ecosystem, err := translateEcosystem(ecosystem)
	if err != nil {
		return common.DepsDevVersionResponse{}, err
	}

	// replace any slashes in the package name with a colon
	if ecosystem == "maven" {
		// for maven, we need to replace the slashes with colons
		packageName = strings.ReplaceAll(packageName, "/", ":")
	}

	// make sure the package name is url encoded
	packageName = url.PathEscape(packageName)
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return common.DepsDevVersionResponse{}, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", depsDevAPIURL, ecosystem, packageName, version), nil)
	if err != nil {
		return common.DepsDevVersionResponse{}, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return common.DepsDevVersionResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return common.DepsDevVersionResponse{}, fmt.Errorf("could not get version information: %s", res.Status)
	}

	var response common.DepsDevVersionResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return common.DepsDevVersionResponse{}, err
	}

	return response, nil
}
