package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"golang.org/x/time/rate"
)

type openSourceInsightService struct {
	httpClient           *http.Client
	depsDevRateLimiter   rate.Limiter
	packagistRateLimiter rate.Limiter
}

var _ shared.OpenSourceInsightService = (*openSourceInsightService)(nil) // Ensure openSourceInsightService implements shared.OpenSourceInsightService interface

func NewOpenSourceInsightService() *openSourceInsightService {
	return &openSourceInsightService{
		httpClient:           &http.Client{Transport: utils.EgressTransport},
		depsDevRateLimiter:   *rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
		packagistRateLimiter: *rate.NewLimiter(rate.Every(100*time.Millisecond), 5),
	}
}

var openSourceInsightsAPIURL = "https://api.deps.dev/v3"
var packagistAPIURL = "https://repo.packagist.org/p2"
var goModuleProxyURL = "https://proxy.golang.org"

func combineNamespaceAndName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	return namespace + "/" + name
}

func (s *openSourceInsightService) GetProject(ctx context.Context, projectID string) (dtos.OpenSourceInsightsProjectResponse, error) {
	// make sure the projectID (which is usually a github repository url) is url encoded
	projectID = url.PathEscape(projectID)

	if err := s.depsDevRateLimiter.Wait(ctx); err != nil {
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
	case "composer":
		return "composer", nil
	}

	return "", fmt.Errorf("ecosystem %s is not supported", ecosystem)
}

func (s *openSourceInsightService) GetVersion(ctx context.Context, purl packageurl.PackageURL) (dtos.OpenSourceInsightsVersionResponse, error) {
	if purl.Type == "golang" && purl.Version != "" {
		return s.getGoVersion(ctx, purl)
	}

	return s.getVersion(ctx, purl)
}

func (s *openSourceInsightService) getGoVersion(ctx context.Context, purl packageurl.PackageURL) (dtos.OpenSourceInsightsVersionResponse, error) {
	// deps.dev expects v-prefixed Go versions; always try that first, then without.
	vPurl := purl
	vPurl.Version = "v" + strings.TrimPrefix(purl.Version, "v")
	if response, err := s.getVersion(ctx, vPurl); err == nil {
		return response, nil
	}

	noVPurl := purl
	noVPurl.Version = strings.TrimPrefix(purl.Version, "v")
	if response, err := s.getVersion(ctx, noVPurl); err == nil {
		return response, nil
	}

	// deps.dev is case-sensitive for Go module paths, but PURLs lowercase the namespace.
	// Resolve the canonical casing via the Go module proxy, which accepts !-encoded paths.
	canonicalPurl, err := resolveGoModuleCanonicalPurl(ctx, s.httpClient, purl)
	if err != nil {
		return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("could not get version information for %s: %w", purl.String(), err)
	}
	return s.getVersion(ctx, canonicalPurl)
}

// resolveGoModuleCanonicalPurl fetches the go.mod from the Go module proxy to get the
// correctly-cased module path, then returns an updated purl with the canonical namespace/name.
// The proxy accepts case-insensitive paths, so we can pass the lowercased PURL path directly.
func resolveGoModuleCanonicalPurl(ctx context.Context, client *http.Client, purl packageurl.PackageURL) (packageurl.PackageURL, error) {
	modulePath := combineNamespaceAndName(purl.Namespace, purl.Name)
	modURL := fmt.Sprintf("%s/%s/@v/%s.mod", goModuleProxyURL, modulePath, purl.Version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modURL, nil)
	if err != nil {
		return purl, err
	}

	res, err := client.Do(req)
	if err != nil {
		return purl, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return purl, fmt.Errorf("go module proxy returned %s for %s", res.Status, modURL)
	}

	// Parse the module directive from go.mod — it's always the first non-blank line starting with "module "
	var canonicalPath string
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			canonicalPath = strings.TrimSpace(rest)
			break
		}
	}
	if canonicalPath == "" {
		return purl, fmt.Errorf("could not find module directive in go.mod for %s", modulePath)
	}

	// Split canonical path back into namespace + name for the purl
	lastSlash := strings.LastIndex(canonicalPath, "/")
	if lastSlash == -1 {
		purl.Namespace = ""
		purl.Name = canonicalPath
	} else {
		purl.Namespace = canonicalPath[:lastSlash]
		purl.Name = canonicalPath[lastSlash+1:]
	}
	return purl, nil
}

func (s *openSourceInsightService) getVersion(ctx context.Context, purl packageurl.PackageURL) (dtos.OpenSourceInsightsVersionResponse, error) {
	// make sure the package name is url encoded
	packageName := combineNamespaceAndName(purl.Namespace, purl.Name)
	if purl.Type == "maven" {
		// for maven, we need to replace the slashes with colons before encoding
		packageName = strings.ReplaceAll(packageName, "/", ":")
	}
	packageName = url.PathEscape(packageName)

	var req *http.Request
	var res *http.Response
	var response dtos.OpenSourceInsightsVersionResponse

	switch purl.Type {
	case "composer":
		if err := s.packagistRateLimiter.Wait(ctx); err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}
		packageNameDecoded, err := url.PathUnescape(packageName)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("invalid packageName for packagist alternative, could not get version information: %s", packageName)
		}
		parts := strings.SplitN(packageNameDecoded, "/", 2)
		if len(parts) < 2 {
			return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("invalid packageName for packagist alternative, could not get version information: %s", packageName)
		}
		vendor := parts[0]
		packageIdentifier := parts[1]

		req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s.json", packagistAPIURL, vendor, packageIdentifier), nil)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}

		res, err = s.httpClient.Do(req)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}

		if res.StatusCode != http.StatusOK {
			return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("could not get version information: %s", res.Status)
		}

		var packagistResponse dtos.PackagistPackageResponse
		if err := json.NewDecoder(res.Body).Decode(&packagistResponse); err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}

		packagistPackageKey := vendor + "/" + packageIdentifier

		packagistToDepsDev, err := transformer.TransformPackagistToDepsDev(packagistResponse, packagistPackageKey, purl.Version)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}
		defer res.Body.Close()

		return packagistToDepsDev, nil
	default:
		ecosystemName, err := translateEcosystem(purl.Type)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}
		url := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s", openSourceInsightsAPIURL, ecosystemName, packageName, purl.Version)
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}

		res, err = s.httpClient.Do(req)
		if err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}

		if res.StatusCode != http.StatusOK {
			return dtos.OpenSourceInsightsVersionResponse{}, fmt.Errorf("could not get version information: %s", res.Status)
		}

		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return dtos.OpenSourceInsightsVersionResponse{}, err
		}
		defer res.Body.Close()
	}

	return response, nil
}
