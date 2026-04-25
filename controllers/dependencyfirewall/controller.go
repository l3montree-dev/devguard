// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package dependencyfirewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var depProxyTracer = otel.Tracer("devguard/dependency-proxy")

type ProxyType string

const (
	NPMProxy  ProxyType = "npm"
	GoProxy   ProxyType = "go"
	PyPIProxy ProxyType = "pypi"
)

type DependencyProxyCache struct {
	CacheDir string
}
type DependencyProxyConfigs struct {
	Rules         []string `json:"rules"`
	MinReleaseAge int      `json:"minReleaseAge"` // in hours
}

type DependencyProxyController struct {
	assetRepository        shared.AssetRepository
	projectRepository      shared.ProjectRepository
	orgRepository          shared.OrganizationRepository
	dependencyProxyService shared.DependencyProxySecretService
	maliciousChecker       shared.MaliciousPackageChecker
	cacheDir               string
	client                 *http.Client
}

// TrimProxyPrefix strips the /api/v1/dependency-proxy/[secret/]<ecosystem> prefix from the path.
// The secret segment is optional to support routes with and without a secret.
func TrimProxyPrefix(path string, ecosystem ProxyType) string {
	var re *regexp.Regexp
	switch ecosystem {
	case NPMProxy:
		re = npmProxyPrefixRe
	case GoProxy:
		re = goProxyPrefixRe
	case PyPIProxy:
		re = pypiProxyPrefixRe
	default:
		return path
	}
	encodedPackage := re.ReplaceAllString(path, "")
	decodedPackage, err := url.PathUnescape(encodedPackage)
	if err != nil {
		return encodedPackage
	}
	return decodedPackage
}

func NewDependencyProxyController(
	dependencyProxyService shared.DependencyProxySecretService,
	config DependencyProxyCache,
	maliciousChecker shared.MaliciousPackageChecker,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
) *DependencyProxyController {
	if maliciousChecker == nil {
		panic("maliciousChecker must not be nil: dependency proxy firewall would be silently disabled")
	}
	return &DependencyProxyController{
		dependencyProxyService: dependencyProxyService,
		maliciousChecker:       maliciousChecker,
		cacheDir:               config.CacheDir,
		assetRepository:        assetRepository,
		projectRepository:      projectRepository,
		orgRepository:          orgRepository,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: utils.EgressTransport,
		},
	}
}

func (d *DependencyProxyController) getCachePath(proxyType ProxyType, requestPath string) string {
	cleanPath := strings.TrimPrefix(requestPath, "/")
	subDir := string(proxyType)
	return filepath.Join(d.cacheDir, subDir, cleanPath)
}

func (d *DependencyProxyController) fetchFromUpstream(ctx context.Context, proxyType ProxyType, upstreamURL, requestPath string, headers http.Header, body io.Reader) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url, err := url.JoinPath(upstreamURL, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	slog.Debug("Fetching from upstream", "proxy", proxyType, "url", url, "bodyPresent", body != nil)

	// Determine HTTP method based on body presence
	method := "GET"
	if body != nil {
		method = "POST"
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward Content-Type for POST requests
	if method == "POST" {
		if contentType := headers.Get("Content-Type"); contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return data, resp.Header, resp.StatusCode, nil
}

func (d *DependencyProxyController) cacheData(cachePath string, data []byte) error {
	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// CacheDataWithIntegrity stores data and its SHA256 hash for integrity verification
func (d *DependencyProxyController) CacheDataWithIntegrity(cachePath string, data []byte) error {
	// Write the data file
	if err := d.cacheData(cachePath, data); err != nil {
		return err
	}

	// Calculate and store SHA256 hash
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])
	hashPath := cachePath + ".sha256"

	if err := os.WriteFile(hashPath, []byte(hashStr), 0644); err != nil {
		slog.Warn("Failed to write integrity hash", "path", hashPath, "error", err)
		return err
	}

	return nil
}

func (d *DependencyProxyController) GetDependencyProxyURLs(ctx shared.Context) error {
	//get registry url from env
	registryURL := os.Getenv("DEPENDENCY_PROXY_BASE_URL")
	if registryURL == "" {
		registryURL = "https://api.main.devguard.org/api/v1/dependency-proxy"
	}

	var secret uuid.UUID

	reqCtx := ctx.Request().Context()
	if asset, err := shared.MaybeGetAsset(ctx); err == nil {
		proxy, err := d.dependencyProxyService.GetOrCreateByAssetID(reqCtx, asset.GetID())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to get or create dependency proxy for asset: %v", err))
		}
		secret = proxy.Secret
	} else if project, err := shared.MaybeGetProject(ctx); err == nil {
		proxy, err := d.dependencyProxyService.GetOrCreateByProjectID(reqCtx, project.GetID())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to get or create dependency proxy for project: %v", err))
		}
		secret = proxy.Secret
	} else if org, err := shared.MaybeGetOrganization(ctx); err == nil {
		proxy, err := d.dependencyProxyService.GetOrCreateByOrgID(reqCtx, org.GetID())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to get or create dependency proxy for organization: %v", err))
		}
		secret = proxy.Secret
	}

	if secret == uuid.Nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to determine scope for dependency proxy")
	}

	proxies := map[string]string{}
	proxies["npm"] = registryURL + "/" + secret.String() + "/npm/"
	proxies["go"] = registryURL + "/" + secret.String() + "/go/"
	proxies["pypi"] = registryURL + "/" + secret.String() + "/pypi/simple/"

	return ctx.JSON(http.StatusOK, proxies)
}

func (d *DependencyProxyController) GetDependencyProxyConfigs(c shared.Context) (DependencyProxyConfigs, error) {
	var configs DependencyProxyConfigs

	secret := c.Param("secret")
	uuidSecret, err := uuid.Parse(secret)
	if err != nil {
		return configs, fmt.Errorf("invalid dependency proxy secret: %w", err)
	}

	scope, uuid, err := d.dependencyProxyService.GetModelBySecret(c.Request().Context(), uuidSecret)
	if err != nil {
		return configs, fmt.Errorf("failed to get dependency proxy model by secret: %w", err)
	}

	var configFilesJSON any

	switch scope {
	case "asset":
		asset, err := d.assetRepository.Read(c.Request().Context(), nil, uuid)
		if err != nil {
			return configs, fmt.Errorf("failed to read asset: %w", err)
		}

		configFilesJSON = asset.ConfigFiles["dependency-proxy-configs"]

	case "project":
		project, err := d.projectRepository.Read(c.Request().Context(), nil, uuid)
		if err != nil {
			return configs, fmt.Errorf("failed to read project: %w", err)
		}
		configFilesJSON = project.ConfigFiles["dependency-proxy-configs"]
	case "organization":
		org, err := d.orgRepository.Read(c.Request().Context(), nil, uuid)
		if err != nil {
			return configs, fmt.Errorf("failed to read organization: %w", err)
		}
		configFilesJSON = org.ConfigFiles["dependency-proxy-configs"]
	default:
		return configs, fmt.Errorf("invalid proxy scope: %s", scope)
	}

	if configFilesJSON != nil {
		s, ok := configFilesJSON.(string)
		if !ok {
			return configs, fmt.Errorf("unexpected config file json type: %T", configFilesJSON)
		}
		var raw struct {
			Rules         string `json:"rules"`
			MinReleaseAge int    `json:"minReleaseAge"`
		}
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return configs, fmt.Errorf("failed to unmarshal config file json into configs: %w", err)
		}
		configs.MinReleaseAge = raw.MinReleaseAge
		for _, line := range strings.Split(raw.Rules, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				configs.Rules = append(configs.Rules, line)
			}
		}
	}

	return configs, nil
}

// CacheReleaseTime stores the release time for a cached entry to enable MinReleaseAge checks on cache hits.
func (d *DependencyProxyController) CacheReleaseTime(cachePath string, releaseTime time.Time) error {
	if releaseTime.IsZero() {
		return nil
	}
	return os.WriteFile(cachePath+".releasetime", []byte(releaseTime.UTC().Format(time.RFC3339Nano)), 0644)
}

// ReadCachedReleaseTime reads the stored release time for a cached entry.
func (d *DependencyProxyController) ReadCachedReleaseTime(cachePath string) (time.Time, bool) {
	data, err := os.ReadFile(cachePath + ".releasetime")
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// VerifyCacheIntegrity checks if the cached data matches its stored hash
func (d *DependencyProxyController) VerifyCacheIntegrity(cachePath string, data []byte) bool {
	hashPath := cachePath + ".sha256"

	// Read stored hash
	storedHashBytes, err := os.ReadFile(hashPath)
	if err != nil {
		// If hash file doesn't exist, consider it valid for backward compatibility
		// but log a warning
		if os.IsNotExist(err) {
			slog.Debug("No integrity hash found for cached file", "path", cachePath)
			return true
		}
		slog.Warn("Failed to read integrity hash", "path", hashPath, "error", err)
		return false
	}

	storedHash := string(storedHashBytes)

	// Calculate current hash
	hash := sha256.Sum256(data)
	currentHash := hex.EncodeToString(hash[:])

	// Compare
	if currentHash != storedHash {
		slog.Error("Cache integrity verification failed",
			"path", cachePath,
			"expected", storedHash,
			"actual", currentHash)
		return false
	}

	return true
}

func (d *DependencyProxyController) ParsePackageFromPath(proxyType ProxyType, path string) (string, string) {
	switch proxyType {
	case NPMProxy:
		if strings.HasSuffix(path, ".tgz") {
			parts := strings.Split(path, "/-/")
			if len(parts) == 2 {
				pkgName := strings.TrimPrefix(parts[0], "/")
				filename := strings.TrimSuffix(parts[1], ".tgz")

				// For scoped packages like @babel/core, the tarball is named core-7.23.0.tgz
				// For regular packages like lodash, the tarball is named lodash-4.17.21.tgz
				var expectedPrefix string
				if strings.HasPrefix(pkgName, "@") {
					// Scoped package: @scope/name -> use just "name" as prefix
					if idx := strings.LastIndex(pkgName, "/"); idx != -1 {
						expectedPrefix = pkgName[idx+1:]
					}
				} else {
					// Regular package: use full package name
					expectedPrefix = pkgName
				}

				version := strings.TrimPrefix(filename, expectedPrefix+"-")
				return pkgName, version
			}
		}
		pkgName := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/")
		return pkgName, ""

	case GoProxy:
		matches := goPathRe.FindStringSubmatch(path)
		if len(matches) > 1 {
			moduleName := strings.TrimPrefix(matches[1], "/")
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				if matches[2] == "list" {
					return strings.TrimRight(moduleName, "/"), ""
				}
				version = strings.TrimSuffix(strings.TrimSuffix(matches[2], ".info"), ".mod")
				version = strings.TrimSuffix(version, ".zip")
			}
			return strings.TrimRight(moduleName, "/"), version
		}

	case PyPIProxy:
		// PyPI simple API: /simple/<package-name>/ or /packages/<filename>
		// Extract package name from path like /simple/django/ or /packages/django-3.2.0-py3-none-any.whl
		path = strings.TrimPrefix(path, "/")
		if after, ok := strings.CutPrefix(path, "simple/"); ok {
			pkgName := after
			pkgName = strings.TrimSuffix(pkgName, "/")
			return pkgName, ""
		} else if strings.HasPrefix(path, "/packages/") {
			filename := filepath.Base(path)
			// Try to extract package name and version from filename
			matches := pypiFilenameRe.FindStringSubmatch(filename)
			if len(matches) > 2 {
				return matches[1], matches[2]
			}
		}
	}

	return "", ""
}

// matchPattern matches a packagePurl against a pattern that may contain '*' wildcards.
// - *pattern* → contains
// - *pattern  → contains (suffix match)
// - pattern*  → starts with
// - a*b       → starts with "a" and ends with "b"
// - pattern   → exact match
func matchPattern(pattern, packagePurl string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return packagePurl == pattern
	}
	// First part must be a prefix (empty if pattern starts with *)
	if parts[0] != "" && !strings.HasPrefix(packagePurl, parts[0]) {
		return false
	}
	// Last part must be a suffix (empty if pattern ends with *)
	if parts[len(parts)-1] != "" && !strings.HasSuffix(packagePurl, parts[len(parts)-1]) {
		return false
	}
	// Middle parts must appear in order
	rest := packagePurl
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(rest, part)
		if idx == -1 {
			return false
		}
		rest = rest[idx+len(part):]
	}
	return true
}

func (d *DependencyProxyController) CheckNotAllowedPackage(ctx context.Context, proxyType ProxyType, path string, configs DependencyProxyConfigs) (bool, string) {
	var packageName, version, packagePurl string
	if strings.HasPrefix(path, "pkg:") {
		// Path is already a PURL — use it directly.
		packagePurl = path
	} else {
		packageName, version = d.ParsePackageFromPath(proxyType, path)
		if packageName == "" {
			return false, ""
		}
		packagePurl = fmt.Sprintf("pkg:%s/%s", proxyType, packageName)
		if version != "" {
			packagePurl += "@" + version
		}
	}

	// Rules are applied in order like gitignore: last matching rule wins.
	// A rule prefixed with "!" negates the match (allowlist).
	blocked := false
	matchedRule := ""
	for _, rule := range configs.Rules {
		negate := strings.HasPrefix(rule, "!")
		pattern := strings.TrimPrefix(rule, "!")

		matched := matchPattern(pattern, packagePurl)

		if matched {
			blocked = !negate
			matchedRule = rule
		}
	}

	if blocked {
		displayName := packageName
		if displayName == "" {
			displayName = packagePurl
		}
		return true, fmt.Sprintf("Package %s is not allowed by rule: %s", displayName, matchedRule)
	}
	return false, ""
}

func (d *DependencyProxyController) checkMaliciousPackage(ctx context.Context, proxyType ProxyType, path string) (bool, string) {
	packageName, version := d.ParsePackageFromPath(proxyType, path)
	if packageName == "" {
		return false, ""
	}

	ecosystem := ""
	switch proxyType {
	case NPMProxy:
		ecosystem = "npm"
	case GoProxy:
		ecosystem = "go"
	case PyPIProxy:
		ecosystem = "pypi"
	}

	slog.Debug("Checking package against malicious database", "ecosystem", ecosystem, "package", packageName, "version", version)
	isMalicious, entry, err := d.maliciousChecker.IsMalicious(ctx, ecosystem, packageName, version)
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", proxyType, "error", err)
		return false, ""
	}

	if isMalicious {
		reason := fmt.Sprintf("Package %s is flagged as malicious (ID: %s)", packageName, entry.ID)
		if entry.Summary != "" {
			reason += ": " + entry.Summary
		}
		return true, reason
	}

	return false, ""
}

func (d *DependencyProxyController) blockNotAllowedPackage(c shared.Context, proxyType ProxyType, path, reason string) error {
	span := trace.SpanFromContext(c.Request().Context())
	span.SetAttributes(
		attribute.Bool("proxy.not_allowed_blocked", true),
		attribute.String("proxy.block_reason", reason),
	)
	span.SetStatus(codes.Error, "package blocked by rule")

	c.Response().Header().Set("X-Not-Allowed-Package", "blocked")

	slog.Warn("BLOCKED NOT ALLOWED PACKAGE", "path", path, "reason", reason)

	packageName, _ := d.ParsePackageFromPath(proxyType, path)
	if packageName == "" {
		packageName = "unknown"
	}
	span.SetAttributes(attribute.String("proxy.package", packageName))

	response := map[string]any{
		"error":   "Forbidden",
		"message": "This package has been blocked by the dependency proxy rules",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	return c.JSON(http.StatusForbidden, response)
}

func (d *DependencyProxyController) blockMaliciousPackage(c shared.Context, proxyType ProxyType, path, reason string) error {
	span := trace.SpanFromContext(c.Request().Context())
	span.SetAttributes(
		attribute.Bool("proxy.malicious_blocked", true),
		attribute.String("proxy.block_reason", reason),
	)
	span.SetStatus(codes.Error, "malicious package blocked")

	c.Response().Header().Set("X-Malicious-Package", "blocked")

	slog.Warn("BLOCKED MALICIOUS PACKAGE", "path", path, "reason", reason)

	// Extract package name from path
	packageName, _ := d.ParsePackageFromPath(proxyType, path)
	if packageName == "" {
		packageName = "unknown"
	}
	span.SetAttributes(attribute.String("proxy.package", packageName))

	response := map[string]any{
		"error":   "Forbidden",
		"message": "This package has been blocked by the malicious package firewall",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	return c.JSON(http.StatusForbidden, response)
}

func (d *DependencyProxyController) blockTooNewPackage(c shared.Context, proxyType ProxyType, path string, releaseTime time.Time, minReleaseAge int) error {
	span := trace.SpanFromContext(c.Request().Context())
	span.SetAttributes(
		attribute.Bool("proxy.too_new_blocked", true),
	)
	span.SetStatus(codes.Error, "package too new")

	c.Response().Header().Set("X-Too-New-Package", "blocked")

	packageName, _ := d.ParsePackageFromPath(proxyType, path)
	if packageName == "" {
		packageName = "unknown"
	}
	span.SetAttributes(attribute.String("proxy.package", packageName))

	reason := fmt.Sprintf("Package %s was released %s ago, which is less than the required minimum of %d hours",
		packageName,
		time.Since(releaseTime).Round(time.Minute),
		minReleaseAge,
	)
	slog.Warn("BLOCKED TOO NEW PACKAGE", "path", path, "reason", reason)

	response := map[string]any{
		"error":   "Forbidden",
		"message": "This package has been blocked because it was released too recently",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	return c.JSON(http.StatusForbidden, response)
}
