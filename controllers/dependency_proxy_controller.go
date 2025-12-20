// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/labstack/echo/v4"
)

const (
	npmRegistry  = "https://registry.npmjs.org"
	goProxyURL   = "https://proxy.golang.org"
	pypiRegistry = "https://pypi.org"
)

type ProxyType string

const (
	NPMProxy  ProxyType = "npm"
	GoProxy   ProxyType = "go"
	PyPIProxy ProxyType = "pypi"
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

func (d *DependencyProxyController) ProxyPyPI(c shared.Context) error {
	return d.handleProxy(c, PyPIProxy, pypiRegistry, "/api/v1/dependency-proxy/pypi")
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

	// Block all requests if malicious package database is not yet loaded
	if d.maliciousChecker != nil && !d.maliciousChecker.IsReady() {
		slog.Warn("Blocking request - malicious package database not yet loaded", "proxy", proxyType, "path", requestPath)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Service is initializing, please try again in a moment")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(proxyType, requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", proxyType, "path", requestPath, "reason", reason)
			// Also remove from cache if it exists to prevent serving cached malicious content
			cachePath := d.getCachePath(proxyType, requestPath)
			if err := os.Remove(cachePath); err == nil {
				slog.Info("Removed malicious package from cache", "path", cachePath)
			}
			return d.blockMaliciousPackage(c, proxyType, requestPath, reason)
		}
	}

	cachePath := d.getCachePath(proxyType, requestPath)

	// Check cache
	if d.isCached(proxyType, cachePath) {
		slog.Debug("Cache hit", "proxy", proxyType, "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			// Verify cache integrity
			if d.VerifyCacheIntegrity(cachePath, data) {
				return d.writeResponse(c, data, proxyType, requestPath, true)
			}
			slog.Warn("Cache integrity verification failed, refetching", "proxy", proxyType, "path", requestPath)
			// Remove corrupted cache
			os.Remove(cachePath)
			os.Remove(cachePath + ".sha256")
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

	// Cache successful responses with integrity verification
	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
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
	case PyPIProxy:
		if strings.HasSuffix(cachePath, ".whl") || strings.HasSuffix(cachePath, ".tar.gz") {
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
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := upstreamURL + requestPath
	slog.Debug("Fetching from upstream", "proxy", proxyType, "url", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward important headers for PyPI
	if proxyType == PyPIProxy {
		if userAgent := headers.Get("User-Agent"); userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		if accept := headers.Get("Accept"); accept != "" {
			req.Header.Set("Accept", accept)
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
	case PyPIProxy:
		if strings.HasSuffix(path, ".whl") {
			return "application/zip"
		} else if strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".zip") {
			return "application/octet-stream"
		} else if strings.Contains(path, "/simple/") {
			return "text/html"
		}
		return "application/octet-stream"
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
		pkgName := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/")
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
			return strings.TrimRight(moduleName, "/"), version
		}

	case PyPIProxy:
		// PyPI simple API: /simple/<package-name>/ or /packages/<filename>
		// Extract package name from path like /simple/django/ or /packages/django-3.2.0-py3-none-any.whl
		if after, ok := strings.CutPrefix(path, "/simple/"); ok {
			pkgName := after
			pkgName = strings.TrimSuffix(pkgName, "/")
			return pkgName, ""
		} else if strings.HasPrefix(path, "/packages/") {
			filename := filepath.Base(path)
			// Try to extract package name and version from filename
			re := regexp.MustCompile(`^([a-zA-Z0-9_-]+)-([0-9\.]+[a-zA-Z0-9\.]*)(?:-|\.).*$`)
			matches := re.FindStringSubmatch(filename)
			if len(matches) > 2 {
				return matches[1], matches[2]
			}
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
	case PyPIProxy:
		ecosystem = "pypi"
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

func (d *DependencyProxyController) blockMaliciousPackage(c shared.Context, proxyType ProxyType, path, reason string) error {
	c.Response().Header().Set("X-Malicious-Package", "blocked")

	slog.Warn("BLOCKED MALICIOUS PACKAGE", "path", path, "reason", reason)

	// Extract package name from path for metrics
	packageName, _ := d.parsePackageFromPath(proxyType, path)
	if packageName == "" {
		packageName = "unknown"
	}

	monitoring.MaliciousPackageBlocked.WithLabelValues(string(proxyType), packageName).Inc()

	response := map[string]any{
		"error":   "Forbidden",
		"message": "This package has been blocked by the malicious package firewall",
		"reason":  reason,
		"path":    path,
		"blocked": true,
	}

	return c.JSON(http.StatusForbidden, response)
}
