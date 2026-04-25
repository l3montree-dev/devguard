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

package dependencyfirewall

import (
	"context"
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

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const pypiRegistry = "https://pypi.org"

var (
	pypiProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?pypi(?:/|$)`)
	pypiFilenameRe    = regexp.MustCompile(`^([a-zA-Z0-9_-]+)-([0-9\.]+[a-zA-Z0-9\.]*)(?:-|\.).*$`)
)

// PythonDependencyProxyController handles PyPI dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type PythonDependencyProxyController struct {
	*DependencyProxyController
}

func NewPythonDependencyProxyController(controller *DependencyProxyController) *PythonDependencyProxyController {
	return &PythonDependencyProxyController{DependencyProxyController: controller}
}

type pypiEcosystem struct{}

var pypi pypiEcosystem

func (pypiEcosystem) name() string { return "pypi" }

func (pypiEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, pypiProxyPrefixRe)
}

func (pypiEcosystem) parsePackage(path string) (string, string) {
	path = strings.TrimPrefix(path, "/")
	if after, ok := strings.CutPrefix(path, "simple/"); ok {
		return strings.TrimSuffix(after, "/"), ""
	} else if strings.HasPrefix(path, "packages/") {
		filename := filepath.Base(path)
		matches := pypiFilenameRe.FindStringSubmatch(filename)
		if len(matches) > 2 {
			return matches[1], matches[2]
		}
	}
	return "", ""
}

func (pypiEcosystem) isCached(cachePath string) bool {
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

func (pypiEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
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

// ProxyPyPIPackage handles explicit-version PyPI package downloads (from /packages/).
// Route: GET /pypi/packages/*
func (d *PythonDependencyProxyController) ProxyPyPIPackage(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	requestPath := pypi.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.pypi",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "pypi"),
			attribute.String("proxy.type", "package"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	slog.Info("Proxy request", "proxy", "pypi", "type", "package", "method", c.Request().Method, "path", requestPath)

	cachePath, err := d.getCachePath(pypi, requestPath)
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "pypi", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, pypi, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "pypi", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, pypi, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	if blocked, reason := d.checkMaliciousPackage(ctx, pypi, requestPath); blocked {
		slog.Warn("Blocked malicious package", "proxy", "pypi", "path", requestPath, "reason", reason)
		if err := os.Remove(cachePath); err == nil {
			slog.Info("Removed malicious package from cache", "path", cachePath)
		}
		return d.blockMaliciousPackage(c, pypi, requestPath, reason)
	}

	if pypi.isCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "pypi", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			if d.VerifyCacheIntegrity(cachePath, data) {
				if configs.MinReleaseAge > 0 {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
							return d.blockTooNewPackage(c, pypi, requestPath, releaseTime, configs.MinReleaseAge)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return pypi.writeResponse(c, data, requestPath, true)
					}
					// No cached release time — fall through to upstream to retrieve it.
					slog.Debug("No cached release time for MinReleaseAge check, refetching", "proxy", "pypi", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return pypi.writeResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "pypi", "path", requestPath)
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "pypi", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchPyPIFromUpstream(ctx, requestPath, c.Request().Header)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "pypi", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "pypi", "error", err)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return pypi.writeResponse(c, data, requestPath, false)
}

// ProxyPyPISimple handles PyPI /simple/ metadata requests, resolving the latest version before checking rules.
// Route: GET /pypi/simple/:package
func (d *PythonDependencyProxyController) ProxyPyPISimple(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	pkgName := c.Param("package")
	requestPath := pypi.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.pypi",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "pypi"),
			attribute.String("proxy.type", "simple"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	slog.Info("Proxy request", "proxy", "pypi", "type", "simple", "method", c.Request().Method, "path", requestPath)

	cachePath, err := d.getCachePath(pypi, requestPath)
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "pypi", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchPyPIFromUpstream(ctx, requestPath, c.Request().Header)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "pypi", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	// Fetch the PyPI JSON API to resolve version and release time before checking rules —
	// same pattern as npm metadata: check allowlist and malicious DB with the resolved version.
	var pypiReleaseTime time.Time
	resolvedVersion, releaseTime, ok := d.fetchPyPILatestVersionAndReleaseTime(ctx, pkgName)
	if ok {
		pypiReleaseTime = releaseTime

		notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, pypi, pkgName+"@"+resolvedVersion, configs)
		if notAllowed {
			slog.Warn("Blocked not allowed package", "proxy", "pypi", "path", requestPath, "reason", notAllowedReason)
			return d.blockNotAllowedPackage(c, pypi, requestPath, notAllowedReason)
		}

		slog.Debug("Checking resolved version for malicious package", "package", pkgName, "version", resolvedVersion)
		isMalicious, entry, err := d.maliciousChecker.IsMalicious(ctx, "pypi", pkgName, resolvedVersion)
		if err != nil {
			slog.Error("Error checking malicious package", "proxy", "pypi", "error", err)
			return echo.NewHTTPError(500, "failed to check if package is malicious").WithInternal(err)
		}
		if isMalicious {
			reason := fmt.Sprintf("Package %s@%s is flagged as malicious (ID: %s)", pkgName, resolvedVersion, entry.ID)
			if entry.Summary != "" {
				reason += ": " + entry.Summary
			}
			slog.Warn("Blocked malicious package after version resolution", "proxy", "pypi", "package", pkgName, "version", resolvedVersion, "reason", reason)
			return d.blockMaliciousPackage(c, pypi, requestPath, reason)
		}

		if configs.MinReleaseAge > 0 {
			if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
				return d.blockTooNewPackage(c, pypi, requestPath, releaseTime, configs.MinReleaseAge)
			}
		}
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "pypi", "error", err)
	}

	// Store release time so MinReleaseAge can be enforced on future cache hits.
	if !pypiReleaseTime.IsZero() {
		if err := d.CacheReleaseTime(cachePath, pypiReleaseTime); err != nil {
			slog.Warn("Failed to cache release time", "proxy", "pypi", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return pypi.writeResponse(c, data, requestPath, false)
}

func (d *PythonDependencyProxyController) fetchPyPIFromUpstream(ctx context.Context, requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	requestPath = strings.TrimRight(requestPath, "/")
	url, err := url.JoinPath(pypiRegistry, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	slog.Debug("Fetching from upstream", "proxy", "pypi", "url", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

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

// ExtractPyPIReleaseTime parses a PyPI JSON API response and returns the resolved version and its upload time.
// If version is empty, it uses info.version (the current release).
func (d *PythonDependencyProxyController) ExtractPyPIReleaseTime(data []byte, version string) (string, time.Time, bool) {
	var metadata struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", time.Time{}, false
	}
	if version == "" {
		version = metadata.Info.Version
	}
	files, ok := metadata.Releases[version]
	if !ok || len(files) == 0 {
		return version, time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, files[0].UploadTime)
	if err != nil {
		return version, time.Time{}, false
	}
	return version, t, true
}

// fetchPyPILatestVersionAndReleaseTime fetches the PyPI JSON API and returns the resolved version and its release time.
func (d *PythonDependencyProxyController) fetchPyPILatestVersionAndReleaseTime(ctx context.Context, pkgName string) (string, time.Time, bool) {
	data, _, statusCode, err := d.fetchPyPIFromUpstream(ctx, "/pypi/"+pkgName+"/json", http.Header{})
	if err != nil || statusCode != http.StatusOK {
		return "", time.Time{}, false
	}
	return d.ExtractPyPIReleaseTime(data, "")
}
