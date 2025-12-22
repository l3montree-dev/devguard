// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controllers

import (
	"bytes"
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
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		monitoring.DependencyProxyRequestDuration.WithLabelValues("npm").Observe(duration)
	}()

	// Get the full path after the prefix
	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/api/v1/dependency-proxy/npm")

	// Only allow GET and HEAD for regular npm requests
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	slog.Info("Proxy request", "proxy", "npm", "method", c.Request().Method, "path", requestPath)

	// Block all requests if malicious package database is not yet loaded
	if d.maliciousChecker != nil && !d.maliciousChecker.IsReady() {
		slog.Warn("Blocking request - malicious package database not yet loaded", "proxy", "npm", "path", requestPath)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Service is initializing, please try again in a moment")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(NPMProxy, requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", "npm", "path", requestPath, "reason", reason)
			// Also remove from cache if it exists to prevent serving cached malicious content
			cachePath := d.getCachePath(NPMProxy, requestPath)
			if err := os.Remove(cachePath); err == nil {
				slog.Info("Removed malicious package from cache", "path", cachePath)
			}
			return d.blockMaliciousPackage(c, NPMProxy, requestPath, reason)
		}
	}

	cachePath := d.getCachePath(NPMProxy, requestPath)

	// Check cache
	if d.isNPMCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "npm", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			// Verify cache integrity
			if d.VerifyCacheIntegrity(cachePath, data) {
				return d.writeNPMResponse(c, data, requestPath, true)
			}
			slog.Warn("Cache integrity verification failed, refetching", "proxy", "npm", "path", requestPath)
			// Remove corrupted cache
			os.Remove(cachePath)
			os.Remove(cachePath + ".sha256")
		}
		slog.Warn("Cache read error", "proxy", "npm", "error", err)
	}

	// Fetch from upstream
	data, headers, statusCode, err := d.fetchFromUpstream(NPMProxy, npmRegistry, requestPath, c.Request().Header, nil)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "npm", "status", statusCode)
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
		slog.Warn("Failed to cache response", "proxy", "npm", "error", err)
	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		c.Response().Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	return d.writeNPMResponse(c, data, requestPath, false)
}

func (d *DependencyProxyController) ProxyNPMAudit(c shared.Context) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		monitoring.DependencyProxyRequestDuration.WithLabelValues("npm-audit").Observe(duration)
	}()

	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/api/v1/dependency-proxy/npm")

	slog.Info("Proxy npm audit request", "method", c.Request().Method, "path", requestPath, "contentType", c.Request().Header.Get("Content-Type"))

	// Block all requests if malicious package database is not yet loaded
	if d.maliciousChecker != nil && !d.maliciousChecker.IsReady() {
		slog.Warn("Blocking request - malicious package database not yet loaded", "proxy", "npm-audit", "path", requestPath)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Service is initializing, please try again in a moment")
	}

	// Read the request body
	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		slog.Error("Error reading request body", "proxy", "npm-audit", "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}

	slog.Info("Forwarding npm audit request", "path", requestPath, "bodySize", len(bodyBytes), "body", string(bodyBytes)[:min(len(bodyBytes), 500)])

	// Fetch and forward directly without caching
	data, headers, statusCode, err := d.fetchNPMAuditFromUpstream(requestPath, c.Request().Header, bodyBytes)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", "npm-audit", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	// Forward important headers
	for key, values := range headers {
		for _, value := range values {
			c.Response().Header().Add(key, value)
		}
	}

	fmt.Println(string(data))

	return c.Blob(statusCode, headers.Get("Content-Type"), data)
}

func (d *DependencyProxyController) ProxyGo(c shared.Context) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		monitoring.DependencyProxyRequestDuration.WithLabelValues("go").Observe(duration)
	}()

	// Get the full path after the prefix
	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/api/v1/dependency-proxy/go")

	// Only allow GET and HEAD for Go proxy
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	slog.Info("Proxy request", "proxy", "go", "method", c.Request().Method, "path", requestPath)

	// Block all requests if malicious package database is not yet loaded
	if d.maliciousChecker != nil && !d.maliciousChecker.IsReady() {
		slog.Warn("Blocking request - malicious package database not yet loaded", "proxy", "go", "path", requestPath)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Service is initializing, please try again in a moment")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(GoProxy, requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", "go", "path", requestPath, "reason", reason)
			// Also remove from cache if it exists to prevent serving cached malicious content
			cachePath := d.getCachePath(GoProxy, requestPath)
			if err := os.Remove(cachePath); err == nil {
				slog.Info("Removed malicious package from cache", "path", cachePath)
			}
			return d.blockMaliciousPackage(c, GoProxy, requestPath, reason)
		}
	}

	cachePath := d.getCachePath(GoProxy, requestPath)

	// Check cache
	if d.isGoCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "go", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			// Verify cache integrity
			if d.VerifyCacheIntegrity(cachePath, data) {
				return d.writeGoResponse(c, data, requestPath, true)
			}
			slog.Warn("Cache integrity verification failed, refetching", "proxy", "go", "path", requestPath)
			// Remove corrupted cache
			os.Remove(cachePath)
			os.Remove(cachePath + ".sha256")
		}
		slog.Warn("Cache read error", "proxy", "go", "error", err)
	}

	// Fetch from upstream
	data, headers, statusCode, err := d.fetchFromUpstream(GoProxy, goProxyURL, requestPath, c.Request().Header, nil)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", "go", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "go", "status", statusCode)
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
		slog.Warn("Failed to cache response", "proxy", "go", "error", err)
	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		c.Response().Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	return d.writeGoResponse(c, data, requestPath, false)
}

func (d *DependencyProxyController) ProxyPyPI(c shared.Context) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		monitoring.DependencyProxyRequestDuration.WithLabelValues("pypi").Observe(duration)
	}()

	// Get the full path after the prefix
	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/api/v1/dependency-proxy/pypi")

	// Only allow GET and HEAD for PyPI proxy
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	slog.Info("Proxy request", "proxy", "pypi", "method", c.Request().Method, "path", requestPath)

	// Block all requests if malicious package database is not yet loaded
	if d.maliciousChecker != nil && !d.maliciousChecker.IsReady() {
		slog.Warn("Blocking request - malicious package database not yet loaded", "proxy", "pypi", "path", requestPath)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Service is initializing, please try again in a moment")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(PyPIProxy, requestPath); blocked {
			slog.Warn("Blocked malicious package", "proxy", "pypi", "path", requestPath, "reason", reason)
			// Also remove from cache if it exists to prevent serving cached malicious content
			cachePath := d.getCachePath(PyPIProxy, requestPath)
			if err := os.Remove(cachePath); err == nil {
				slog.Info("Removed malicious package from cache", "path", cachePath)
			}
			return d.blockMaliciousPackage(c, PyPIProxy, requestPath, reason)
		}
	}

	cachePath := d.getCachePath(PyPIProxy, requestPath)

	// Check cache
	if d.isPyPICached(cachePath) {
		slog.Debug("Cache hit", "proxy", "pypi", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			// Verify cache integrity
			if d.VerifyCacheIntegrity(cachePath, data) {
				return d.writePyPIResponse(c, data, requestPath, true)
			}
			slog.Warn("Cache integrity verification failed, refetching", "proxy", "pypi", "path", requestPath)
			// Remove corrupted cache
			os.Remove(cachePath)
			os.Remove(cachePath + ".sha256")
		}
		slog.Warn("Cache read error", "proxy", "pypi", "error", err)
	}

	// Fetch from upstream (forward User-Agent and Accept headers for PyPI)
	data, headers, statusCode, err := d.fetchPyPIFromUpstream(requestPath, c.Request().Header)
	if err != nil {
		slog.Error("Error fetching from upstream", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "pypi", "status", statusCode)
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
		slog.Warn("Failed to cache response", "proxy", "pypi", "error", err)
	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return d.writePyPIResponse(c, data, requestPath, false)
}

func (d *DependencyProxyController) getCachePath(proxyType ProxyType, requestPath string) string {
	cleanPath := strings.TrimPrefix(requestPath, "/")
	subDir := string(proxyType)
	return filepath.Join(d.cacheDir, subDir, cleanPath)
}

func (d *DependencyProxyController) isNPMCached(cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	var maxAge time.Duration
	if strings.HasSuffix(cachePath, ".tgz") {
		maxAge = 24 * time.Hour
	} else {
		maxAge = 1 * time.Hour
	}

	return time.Since(info.ModTime()) < maxAge
}

func (d *DependencyProxyController) isGoCached(cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	var maxAge time.Duration
	if strings.Contains(cachePath, "/@v/") {
		maxAge = 168 * time.Hour // 7 days
	} else {
		maxAge = 1 * time.Hour
	}

	return time.Since(info.ModTime()) < maxAge
}

func (d *DependencyProxyController) isPyPICached(cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}

	var maxAge time.Duration
	if strings.HasSuffix(cachePath, ".whl") || strings.HasSuffix(cachePath, ".tar.gz") {
		maxAge = 168 * time.Hour // 7 days
	} else {
		maxAge = 1 * time.Hour
	}

	return time.Since(info.ModTime()) < maxAge
}

func (d *DependencyProxyController) fetchFromUpstream(proxyType ProxyType, upstreamURL, requestPath string, headers http.Header, body io.Reader) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := upstreamURL + requestPath
	slog.Debug("Fetching from upstream", "proxy", proxyType, "url", url)

	// Determine HTTP method based on body presence
	method := "GET"
	if body != nil {
		method = "POST"
	}

	req, err := http.NewRequest(method, url, body)
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

func (d *DependencyProxyController) fetchNPMAuditFromUpstream(requestPath string, headers http.Header, bodyBytes []byte) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := npmRegistry + requestPath
	slog.Info("Fetching npm audit from upstream", "url", url, "bodySize", len(bodyBytes))

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward Content-Type and Content-Length
	if contentType := headers.Get("Content-Type"); contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.ContentLength = int64(len(bodyBytes))

	// Forward Content-Encoding (important for gzipped requests)
	if contentEncoding := headers.Get("Content-Encoding"); contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	// Forward other important headers
	if userAgent := headers.Get("User-Agent"); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if accept := headers.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	if acceptEncoding := headers.Get("Accept-Encoding"); acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}

	slog.Debug("Upstream request headers", "Content-Type", req.Header.Get("Content-Type"), "Content-Length", req.ContentLength, "Content-Encoding", req.Header.Get("Content-Encoding"))

	resp, err := d.client.Do(req)
	if err != nil {
		slog.Error("Failed to fetch from npm registry", "error", err, "url", url)
		return nil, nil, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read response body", "error", err, "statusCode", resp.StatusCode)
		return nil, nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	slog.Info("Upstream response", "statusCode", resp.StatusCode, "responseSize", len(data))
	if resp.StatusCode >= 400 {
		slog.Error("Upstream error response", "statusCode", resp.StatusCode, "body", string(data)[:min(len(data), 1000)])
	}

	return data, resp.Header, resp.StatusCode, nil
}

func (d *DependencyProxyController) fetchPyPIFromUpstream(requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := pypiRegistry + requestPath
	slog.Debug("Fetching from upstream", "proxy", "pypi", "url", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward important headers for PyPI
	if userAgent := headers.Get("User-Agent"); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if accept := headers.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
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

func (d *DependencyProxyController) writeNPMResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "application/json"
		if strings.HasSuffix(path, ".tgz") {
			contentType = "application/octet-stream"
		}
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "npm")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

func (d *DependencyProxyController) writeGoResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "text/plain; charset=utf-8"
		if strings.HasSuffix(path, ".zip") {
			contentType = "application/zip"
		}
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "go")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

func (d *DependencyProxyController) writePyPIResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "application/octet-stream"
		if strings.HasSuffix(path, ".whl") {
			contentType = "application/zip"
		} else if strings.Contains(path, "/simple/") {
			contentType = "text/html"
		}
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "pypi")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
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
