// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controllers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/labstack/echo/v4"
)

const (
	npmRegistry    = "https://registry.npmjs.org"
	goProxyURL     = "https://proxy.golang.org"
	dockerRegistry = "https://registry-1.docker.io"
)

type ProxyType string

const (
	NPMProxy ProxyType = "npm"
	GoProxy  ProxyType = "go"
	OCIProxy ProxyType = "oci"
)

type DependencyProxyConfig struct {
	CacheDir string
}

type DependencyProxyController struct {
	maliciousChecker *vulndb.MaliciousPackageChecker
	cacheDir         string
	client           *http.Client
}

func NewDependencyProxyController(
	config DependencyProxyConfig,
	maliciousChecker *vulndb.MaliciousPackageChecker,
) *DependencyProxyController {
	return &DependencyProxyController{
		maliciousChecker: maliciousChecker,
		cacheDir:         config.CacheDir,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (d *DependencyProxyController) ProxyNPM(c shared.Context) error {
	return d.handleProxy(c, NPMProxy, npmRegistry, "/api/v1/dependency-proxy/npm")
}

func (d *DependencyProxyController) ProxyGo(c shared.Context) error {
	return d.handleProxy(c, GoProxy, goProxyURL, "/api/v1/dependency-proxy/go")
}

func (d *DependencyProxyController) ProxyOCI(c shared.Context) error {
	return d.handleProxy(c, OCIProxy, dockerRegistry, "/api/v1/dependency-proxy/oci")
}

func (d *DependencyProxyController) handleProxy(c shared.Context, proxyType ProxyType, upstreamURL, prefix string) error {
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	// Get the full path after the prefix
	requestPath := c.Request().URL.Path
	if prefix != "" {
		requestPath = strings.TrimPrefix(requestPath, prefix)
	}

	slog.Info("Proxy request", "proxy", proxyType, "method", c.Request().Method, "path", requestPath)

	// Check for malicious packages
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(proxyType, requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", proxyType, "path", requestPath, "reason", reason)
			return d.blockMaliciousPackage(c, requestPath, reason)
		}
	}

	cachePath := d.getCachePath(proxyType, requestPath)

	// Check cache
	if d.isCached(proxyType, cachePath) {
		slog.Debug("Cache hit", "proxy", proxyType, "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			return d.writeResponse(c, data, proxyType, requestPath, true)
		}
		slog.Warn("Cache read error", "proxy", proxyType, "error", err)
	}

	// Fetch from upstream
	data, headers, statusCode, err := d.fetchFromUpstream(proxyType, upstreamURL, requestPath, c.Request().Header)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", proxyType, "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", proxyType, "status", statusCode)
		// Forward important headers
		for key, values := range headers {
			for _, value := range values {
				c.Response().Header().Add(key, value)
			}
		}
		return c.Blob(statusCode, headers.Get("Content-Type"), data)
	}

	// Cache successful responses
	if err := d.cacheData(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", proxyType, "error", err)
	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		c.Response().Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	return d.writeResponse(c, data, proxyType, requestPath, false)
}

func (d *DependencyProxyController) getCachePath(proxyType ProxyType, requestPath string) string {
	cleanPath := strings.TrimPrefix(requestPath, "/")
	subDir := string(proxyType)
	return filepath.Join(d.cacheDir, subDir, cleanPath)
}

func (d *DependencyProxyController) isCached(proxyType ProxyType, cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	var maxAge time.Duration
	switch proxyType {
	case NPMProxy:
		if strings.HasSuffix(cachePath, ".tgz") {
			maxAge = 24 * time.Hour
		} else {
			maxAge = 1 * time.Hour
		}
	case GoProxy:
		if strings.Contains(cachePath, "/@v/") {
			maxAge = 168 * time.Hour // 7 days
		} else {
			maxAge = 1 * time.Hour
		}
	case OCIProxy:
		if strings.Contains(cachePath, "/blobs/") {
			maxAge = 168 * time.Hour // 7 days
		} else {
			maxAge = 1 * time.Hour
		}
	default:
		maxAge = 1 * time.Hour
	}

	return time.Since(info.ModTime()) < maxAge
}

func (d *DependencyProxyController) fetchFromUpstream(proxyType ProxyType, upstreamURL, requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	url := upstreamURL + requestPath
	slog.Debug("Fetching from upstream", "proxy", proxyType, "url", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward important headers for OCI registry auth
	if proxyType == OCIProxy {
		if auth := headers.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if accept := headers.Get("Accept"); accept != "" {
			req.Header.Set("Accept", accept)
		} else {
			req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")
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

func (d *DependencyProxyController) writeResponse(c shared.Context, data []byte, proxyType ProxyType, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := d.getContentType(proxyType, path)
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", string(proxyType))
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

func (d *DependencyProxyController) getContentType(proxyType ProxyType, path string) string {
	switch proxyType {
	case NPMProxy:
		if strings.HasSuffix(path, ".tgz") {
			return "application/octet-stream"
		}
		return "application/json"
	case GoProxy:
		if strings.HasSuffix(path, ".info") || strings.HasSuffix(path, ".mod") {
			return "text/plain; charset=utf-8"
		} else if strings.HasSuffix(path, ".zip") {
			return "application/zip"
		}
		return "text/plain; charset=utf-8"
	case OCIProxy:
		if strings.Contains(path, "/manifests/") {
			return "application/vnd.docker.distribution.manifest.v2+json"
		} else if strings.Contains(path, "/blobs/") {
			return "application/octet-stream"
		}
		return "application/json"
	}
	return "application/octet-stream"
}

func (d *DependencyProxyController) parsePackageFromPath(proxyType ProxyType, path string) (string, string) {
	switch proxyType {
	case NPMProxy:
		if strings.HasSuffix(path, ".tgz") {
			parts := strings.Split(path, "/-/")
			if len(parts) == 2 {
				pkgName := strings.TrimPrefix(parts[0], "/")
				filename := strings.TrimSuffix(parts[1], ".tgz")
				version := strings.TrimPrefix(filename, strings.ReplaceAll(pkgName, "/", "-")+"-")
				return pkgName, version
			}
		}
		pkgName := strings.TrimPrefix(path, "/")
		return pkgName, ""

	case GoProxy:
		re := regexp.MustCompile(`^/([^@]+)(?:@v/([^/]+))?`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 1 {
			moduleName := matches[1]
			version := ""
			if len(matches) > 2 && matches[2] != "" {
				if matches[2] == "list" {
					return moduleName, ""
				}
				version = strings.TrimSuffix(strings.TrimSuffix(matches[2], ".info"), ".mod")
				version = strings.TrimSuffix(version, ".zip")
			}
			return moduleName, version
		}

	case OCIProxy:
		re := regexp.MustCompile(`^/v2/([^/]+(?:/[^/]+)*)/(?:manifests|blobs)/(.+)$`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 2 {
			return matches[1], matches[2]
		}
	}

	return "", ""
}

func (d *DependencyProxyController) checkMaliciousPackage(proxyType ProxyType, path string) (bool, string) {
	packageName, version := d.parsePackageFromPath(proxyType, path)
	if packageName == "" {
		return false, ""
	}

	ecosystem := ""
	switch proxyType {
	case NPMProxy:
		ecosystem = "npm"
	case GoProxy:
		ecosystem = "go"
	case OCIProxy:
		return false, ""
	}

	slog.Debug("Checking package against malicious database", "ecosystem", ecosystem, "package", packageName, "version", version)

	isMalicious, entry := d.maliciousChecker.IsMalicious(ecosystem, packageName, version)
	if isMalicious {
		reason := fmt.Sprintf("Package %s is flagged as malicious (ID: %s)", packageName, entry.ID)
		if entry.Summary != "" {
			reason += ": " + entry.Summary
		}
		return true, reason
	}

	return false, ""
}

func (d *DependencyProxyController) blockMaliciousPackage(c shared.Context, path, reason string) error {
	c.Response().Header().Set("X-Malicious-Package", "blocked")

	response := map[string]interface{}{
		"error":   "Forbidden",
		"message": "This package has been blocked by the malicious package firewall",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	return c.JSON(http.StatusForbidden, response)
}
