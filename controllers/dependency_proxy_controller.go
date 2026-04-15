// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controllers

import (
	"bytes"
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

	"github.com/bmatcuk/doublestar/v4"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	npmRegistry  = "https://registry.npmjs.org"
	goProxyURL   = "https://proxy.golang.org"
	pypiRegistry = "https://pypi.org"
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
	Rules          []string `json:"rules"`
	MinReleaseTime int      `json:"minReleaseTime"` // in hours
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

// trimProxyPrefix strips the /api/v1/dependency-proxy/[secret/]<ecosystem> prefix from the path.
// The secret segment is optional to support routes with and without a secret.
func TrimProxyPrefix(path string, ecosystem ProxyType) string {
	return regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?`+regexp.QuoteMeta(string(ecosystem))+`(?:/|$)`).ReplaceAllString(path, "")
}

func NewDependencyProxyController(
	dependencyProxyService shared.DependencyProxySecretService,
	config DependencyProxyCache,
	maliciousChecker shared.MaliciousPackageChecker,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
) *DependencyProxyController {
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

func (d *DependencyProxyController) ProxyNPM(c shared.Context) error {

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
	}

	path := c.Request().URL.Path

	// Get the full path after the prefix
	requestPath := TrimProxyPrefix(path, NPMProxy)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	// Only allow GET and HEAD for regular npm requests
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	slog.Info("Proxy request", "proxy", "npm", "method", c.Request().Method, "path", requestPath)

	// Check for malicious packages

	// For requests with explicit versions (e.g., .tgz files or package@version), check immediately
	// For metadata requests (package info without version), we need to fetch first to see which version would be used
	packageName, version := d.ParsePackageFromPath(NPMProxy, requestPath)
	hasExplicitVersion := version != "" || strings.HasSuffix(requestPath, ".tgz")

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, NPMProxy, requestPath, configs)

	if notAllowed {
		return d.blockNotAllowedPackage(c, NPMProxy, requestPath, notAllowedReason)
	}

	hasMalicious, reason := d.checkMaliciousPackage(ctx, NPMProxy, requestPath)

	if hasMalicious {
		slog.Warn("Blocked malicious package", "proxy", "npm", "path", requestPath, "reason", reason)
		// Also remove from cache if it exists to prevent serving cached malicious content
		cachePath := d.getCachePath(NPMProxy, requestPath)
		if err := os.Remove(cachePath); err == nil {
			slog.Info("Removed malicious package from cache", "path", cachePath)
		}
		return d.blockMaliciousPackage(c, NPMProxy, requestPath, reason)
	}

	cachePath := d.getCachePath(NPMProxy, requestPath)

	// Check cache
	if d.isNPMCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "npm", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			// Verify cache integrity
			if d.VerifyCacheIntegrity(cachePath, data) {
				if configs.MinReleaseTime > 0 && !hasExplicitVersion && packageName != "" {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
							return d.blockTooNewPackage(c, NPMProxy, requestPath, releaseTime, configs.MinReleaseTime)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return d.writeNPMResponse(c, data, requestPath, true)
					}
					// No cached release time - fall through to upstream to retrieve it
					slog.Debug("No cached release time for MinReleaseTime check, refetching", "proxy", "npm", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return d.writeNPMResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "npm", "path", requestPath)
				// Remove corrupted cache
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "npm", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Fetch from upstream
	data, headers, statusCode, err := d.fetchFromUpstream(ctx, NPMProxy, npmRegistry, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	resolvedVersion, releaseTime := d.ExtractNPMVersionAndReleaseTimeFromMetadata(data)

	// For metadata requests without explicit version, check the resolved version against malicious database
	if d.maliciousChecker != nil && !hasExplicitVersion && packageName != "" {
		// Parse the JSON response to extract the version that would be installed
		if resolvedVersion != "" {
			slog.Debug("Checking resolved version for malicious package", "package", packageName, "version", resolvedVersion)
			isMalicious, entry := d.maliciousChecker.IsMalicious(ctx, "npm", packageName, resolvedVersion)
			if isMalicious {
				reason := fmt.Sprintf("Package %s@%s is flagged as malicious (ID: %s)", packageName, resolvedVersion, entry.ID)
				if entry.Summary != "" {
					reason += ": " + entry.Summary
				}
				slog.Warn("Blocked malicious package after version resolution", "proxy", "npm", "package", packageName, "version", resolvedVersion, "reason", reason)
				return d.blockMaliciousPackage(c, NPMProxy, requestPath, reason)
			}
		}
	}

	// Check MinReleaseTime for metadata responses (non-tgz)
	if configs.MinReleaseTime > 0 && !hasExplicitVersion && packageName != "" {
		if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
			return d.blockTooNewPackage(c, NPMProxy, requestPath, releaseTime, configs.MinReleaseTime)
		}

	}

	// Cache successful responses with integrity verification
	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "npm", "error", err)
	}

	// Store release time so MinReleaseTime can be enforced on future cache hits
	if !hasExplicitVersion && packageName != "" {
		if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
			slog.Warn("Failed to cache release time", "proxy", "npm", "error", err)
		}

	}

	// Copy important headers from upstream
	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return d.writeNPMResponse(c, data, requestPath, false)
}

func (d *DependencyProxyController) ProxyNPMAudit(c shared.Context) error {
	requestPath := strings.TrimPrefix(c.Request().URL.Path, "/api/v1/dependency-proxy/npm")

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm-audit",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm-audit"),
			attribute.String("proxy.path", requestPath),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy npm audit request", "method", c.Request().Method, "path", requestPath, "contentType", c.Request().Header.Get("Content-Type"))

	// Read the request body
	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		slog.Error("Error reading request body", "proxy", "npm-audit", "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}

	slog.Info("Forwarding npm audit request", "path", requestPath, "bodySize", len(bodyBytes), "body", string(bodyBytes)[:min(len(bodyBytes), 500)])

	// Fetch and forward directly without caching
	data, headers, statusCode, err := d.fetchNPMAuditFromUpstream(ctx, requestPath, c.Request().Header, bodyBytes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
	// Get the full path after the prefix
	requestPath := TrimProxyPrefix(c.Request().URL.Path, GoProxy)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.go",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "go"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	// Only allow GET and HEAD for Go proxy
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
	}

	slog.Info("Proxy request", "proxy", "go", "method", c.Request().Method, "path", requestPath)

	//check config for not allowed patterns before doing anything else to fail fast and avoid unnecessary processing
	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, GoProxy, requestPath, configs)
	if notAllowed {
		return d.blockNotAllowedPackage(c, GoProxy, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(c.Request().Context(), GoProxy, requestPath); blocked {
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
				if configs.MinReleaseTime > 0 && strings.HasSuffix(requestPath, ".info") {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
							return d.blockTooNewPackage(c, GoProxy, requestPath, releaseTime, configs.MinReleaseTime)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return d.writeGoResponse(c, data, requestPath, true)
					}
					// No cached release time - fall through to upstream to retrieve it
					slog.Debug("No cached release time for MinReleaseTime check, refetching", "proxy", "go", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return d.writeGoResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "go", "path", requestPath)
				// Remove corrupted cache
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "go", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Fetch from upstream
	data, headers, statusCode, err := d.fetchFromUpstream(ctx, GoProxy, goProxyURL, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	// Check MinReleaseTime for .info responses (version metadata)
	if configs.MinReleaseTime > 0 && strings.HasSuffix(requestPath, ".info") {
		if releaseTime, ok := d.ExtractGoReleaseTime(data); ok {
			if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
				return d.blockTooNewPackage(c, GoProxy, requestPath, releaseTime, configs.MinReleaseTime)
			}
		}
	}

	// Cache successful responses with integrity verification
	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "go", "error", err)
	}

	// Store release time so MinReleaseTime can be enforced on future cache hits
	if strings.HasSuffix(requestPath, ".info") {
		if releaseTime, ok := d.ExtractGoReleaseTime(data); ok {
			if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
				slog.Warn("Failed to cache release time", "proxy", "go", "error", err)
			}
		}
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
	// Get the full path after the prefix
	requestPath := TrimProxyPrefix(c.Request().URL.Path, PyPIProxy)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.pypi",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "pypi"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	// Only allow GET and HEAD for PyPI proxy
	if c.Request().Method != http.MethodGet && c.Request().Method != http.MethodHead {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
	}

	slog.Info("Proxy request", "proxy", "pypi", "method", c.Request().Method, "path", requestPath)

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning
	if d.maliciousChecker != nil {
		if blocked, reason := d.checkMaliciousPackage(c.Request().Context(), PyPIProxy, requestPath); blocked {
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
				if configs.MinReleaseTime > 0 && strings.Contains(requestPath, "/simple/") {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
							return d.blockTooNewPackage(c, PyPIProxy, requestPath, releaseTime, configs.MinReleaseTime)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return d.writePyPIResponse(c, data, requestPath, true)
					}
					// No cached release time - fall through to upstream to retrieve it
					slog.Debug("No cached release time for MinReleaseTime check, refetching", "proxy", "pypi", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return d.writePyPIResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "pypi", "path", requestPath)
				// Remove corrupted cache
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "pypi", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Fetch from upstream (forward User-Agent and Accept headers for PyPI)
	data, headers, statusCode, err := d.fetchPyPIFromUpstream(ctx, requestPath, c.Request().Header)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	// Check MinReleaseTime for simple/ requests by fetching the PyPI JSON API
	var pypiReleaseTime time.Time
	if configs.MinReleaseTime > 0 && strings.Contains(requestPath, "/simple/") {
		pkgName, _ := d.ParsePackageFromPath(PyPIProxy, requestPath)
		if pkgName != "" {
			if releaseTime, ok := d.fetchPyPILatestReleaseTime(ctx, pkgName); ok {
				pypiReleaseTime = releaseTime
				if time.Since(releaseTime) < time.Duration(configs.MinReleaseTime)*time.Hour {
					return d.blockTooNewPackage(c, PyPIProxy, requestPath, releaseTime, configs.MinReleaseTime)
				}
			}
		}
	}

	// Cache successful responses with integrity verification
	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "pypi", "error", err)
	}

	// Store release time so MinReleaseTime can be enforced on future cache hits
	if !pypiReleaseTime.IsZero() {
		if err := d.CacheReleaseTime(cachePath, pypiReleaseTime); err != nil {
			slog.Warn("Failed to cache release time", "proxy", "pypi", "error", err)
		}
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

func (d *DependencyProxyController) fetchNPMAuditFromUpstream(ctx context.Context, requestPath string, headers http.Header, bodyBytes []byte) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := npmRegistry + requestPath
	slog.Info("Fetching npm audit from upstream", "url", url, "bodySize", len(bodyBytes))

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
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

func (d *DependencyProxyController) fetchPyPIFromUpstream(ctx context.Context, requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	// remove any trailing slashes from requestPath
	requestPath = strings.TrimRight(requestPath, "/")
	url := pypiRegistry + requestPath
	slog.Debug("Fetching from upstream", "proxy", "pypi", "url", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

func (d *DependencyProxyController) GetDependencyProxyURLs(ctx shared.Context) error {
	//get registry url from env
	registryURL := os.Getenv("DEPENDENCY_PROXY_BASE_URL")
	if registryURL == "" {
		registryURL = "https://api.main.devguard.org/dependency-proxy"
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
	proxies["pypi"] = registryURL + "/" + secret.String() + "/pypi/"

	return ctx.JSON(http.StatusOK, proxies)
}

func (d *DependencyProxyController) GetDependencyProxyConfigs(c shared.Context) (DependencyProxyConfigs, error) {
	var configs DependencyProxyConfigs

	secret := c.Param("secret")
	uuidSecret, err := uuid.Parse(secret)
	if err != nil {
		return configs, nil
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
			Rules          string `json:"rules"`
			MinReleaseTime int    `json:"minReleaseTime"`
		}
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return configs, fmt.Errorf("failed to unmarshal config file json into configs: %w", err)
		}
		configs.MinReleaseTime = raw.MinReleaseTime
		configs.Rules = strings.Split(raw.Rules, "\n")
	}

	return configs, nil
}

// CacheReleaseTime stores the release time for a cached entry to enable MinReleaseTime checks on cache hits.
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
		re := regexp.MustCompile(`^/([^@]+)(?:@v/([^/]+))?`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 1 {
			moduleName := matches[1]
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

		// A bare "*" should match any package (across all path segments).
		// doublestar "*" does not cross path separators, so we use "**" instead.
		if pattern == "*" {
			pattern = "**"
		}
		matched, err := doublestar.Match(pattern, packagePurl)
		if err != nil {
			slog.Warn("Invalid rule pattern", "rule", rule, "err", err)
			continue
		}
		// When no version was extracted from the path, also try matching against
		// the pattern with its version suffix stripped (e.g. "pkg:npm/lodash@*" → "pkg:npm/lodash").
		if !matched {
			patternWithoutVersion := pattern
			patternVersion := ""
			lastSlashIdx := strings.LastIndex(pattern, "/")
			patternAfterLastSlash := pattern
			if lastSlashIdx != -1 {
				patternAfterLastSlash = pattern[lastSlashIdx+1:]
			}
			if atIdx := strings.LastIndex(patternAfterLastSlash, "@"); atIdx != -1 {
				patternWithoutVersion = pattern[:lastSlashIdx+1+atIdx]
				patternVersion = pattern[lastSlashIdx+1+atIdx+1:]
				if patternVersion == "*" {
					patternVersion = "**"
				}
			}

			packagePurlWithoutVersion := packagePurl
			packagePurlVersion := ""
			// Only look for the version-separator "@" in the part after the last "/",
			// so that scoped NPM package names like "pkg:npm/@babel/core" are not
			// incorrectly split on the "@" that is part of the scope.
			lastSlashIdx = strings.LastIndex(packagePurl, "/")
			purlAfterLastSlash := packagePurl[lastSlashIdx+1:]
			if atIdx := strings.Index(purlAfterLastSlash, "@"); atIdx != -1 {
				actualIdx := lastSlashIdx + 1 + atIdx
				packagePurlWithoutVersion = packagePurl[:actualIdx]
				packagePurlVersion = packagePurl[actualIdx+1:]
			}

			matched, err = doublestar.Match(patternWithoutVersion, packagePurlWithoutVersion)
			if err != nil {
				slog.Warn("Invalid rule pattern", "rule", rule, "err", err)
				continue
			}
			if matched && patternVersion != "" {
				// If the pattern includes a version requirement, check if the package version satisfies it.
				matched, err = doublestar.Match(patternVersion, packagePurlVersion)
				if err != nil {
					slog.Warn("Invalid version requirement in rule", "rule", rule, "err", err)
					continue
				}
			} else if matched && patternVersion == "" {
				// If the pattern does not include a version requirement, it should match any version of the package.
				matched = true
			} else if matched && patternVersion != "" && packagePurlVersion == "" {
				// If the pattern includes a version requirement but the package does not have a version, it should not match.
				matched = false
			}

			// For non-PURL patterns (e.g. bare names like "react"), also try
			// matching against just the package name without the "pkg:type/" prefix.
			if !matched && !strings.HasPrefix(pattern, "pkg:") {
				purlPrefix := fmt.Sprintf("pkg:%s/", proxyType)
				pkgNameOnly := strings.TrimPrefix(packagePurlWithoutVersion, purlPrefix)
				matched, err = doublestar.Match(patternWithoutVersion, pkgNameOnly)
				if err != nil {
					slog.Warn("Invalid rule pattern (name match)", "rule", rule, "err", err)
					continue
				}
				if matched && patternVersion != "" {
					matched, err = doublestar.Match(patternVersion, packagePurlVersion)
					if err != nil {
						slog.Warn("Invalid version requirement in rule", "rule", rule, "err", err)
						continue
					}
				}
			}
		}
		if matched {
			blocked = !negate
			matchedRule = rule
		}
	}

	if blocked {
		return true, fmt.Sprintf("Package %s is not allowed by rule: %s", packageName, matchedRule)
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

	isMalicious, entry := d.maliciousChecker.IsMalicious(ctx, ecosystem, packageName, version)
	if isMalicious {
		reason := fmt.Sprintf("Package %s is flagged as malicious (ID: %s)", packageName, entry.ID)
		if entry.Summary != "" {
			reason += ": " + entry.Summary
		}
		return true, reason
	}

	return false, ""
}

// ExtractNPMVersionFromMetadata parses NPM package metadata JSON and extracts the "latest" version
// This is used when npx or npm install is called without a specific version
func (d *DependencyProxyController) ExtractNPMVersionAndReleaseTimeFromMetadata(data []byte) (string, time.Time) {
	var metadata struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
		Time map[string]time.Time `json:"time"`
	}

	if err := json.Unmarshal(data, &metadata); err != nil {
		slog.Debug("Failed to parse NPM metadata", "error", err)
		return "", time.Time{}
	}

	return metadata.DistTags.Latest, metadata.Time[metadata.DistTags.Latest]
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

// ExtractGoReleaseTime parses a Go proxy .info response and returns the version time.
func (d *DependencyProxyController) ExtractGoReleaseTime(data []byte) (time.Time, bool) {
	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Time.IsZero() {
		return time.Time{}, false
	}
	return info.Time, true
}

// ExtractPyPIReleaseTime parses a PyPI JSON API response and returns the upload time for a version.
// If version is empty, it uses info.version (the current release).
func (d *DependencyProxyController) ExtractPyPIReleaseTime(data []byte, version string) (time.Time, bool) {
	var metadata struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return time.Time{}, false
	}
	if version == "" {
		version = metadata.Info.Version
	}
	files, ok := metadata.Releases[version]
	if !ok || len(files) == 0 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, files[0].UploadTime)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// fetchPyPILatestReleaseTime fetches the PyPI JSON API and returns the release time of the current version.
func (d *DependencyProxyController) fetchPyPILatestReleaseTime(ctx context.Context, pkgName string) (time.Time, bool) {
	data, _, statusCode, err := d.fetchPyPIFromUpstream(ctx, "/pypi/"+pkgName+"/json", http.Header{})
	if err != nil || statusCode != http.StatusOK {
		return time.Time{}, false
	}
	return d.ExtractPyPIReleaseTime(data, "")
}

func (d *DependencyProxyController) blockTooNewPackage(c shared.Context, proxyType ProxyType, path string, releaseTime time.Time, minReleaseTime int) error {
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
		minReleaseTime,
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
