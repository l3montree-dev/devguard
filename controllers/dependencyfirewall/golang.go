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
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const goProxyURL = "https://proxy.golang.org"

var (
	goProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?go(?:/|$)`)
	goPathRe        = regexp.MustCompile(`^([^@]+)(?:@v/([^/]+))?`)
)

// GoDependencyProxyController handles Go dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type GoDependencyProxyController struct {
	*DependencyProxyController
}

func NewGoDependencyProxyController(controller *DependencyProxyController) *GoDependencyProxyController {
	return &GoDependencyProxyController{DependencyProxyController: controller}
}

type goEcosystem struct{}

var golang goEcosystem

func (goEcosystem) name() string { return "go" }

func (goEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, goProxyPrefixRe)
}

func (goEcosystem) parsePackage(path string) (string, string) {
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
	return "", ""
}

func (goEcosystem) isCached(cachePath string) bool {
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

func (goEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
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

func (d *GoDependencyProxyController) ProxyGo(c shared.Context) error {
	requestPath := golang.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.go",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "go"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	slog.Info("Proxy request", "proxy", "go", "method", c.Request().Method, "path", requestPath)

	packageName, version := golang.parsePackage(requestPath)

	// Requests with an explicit version (.info, .mod, .zip) go through the versioned handler.
	// Requests for @latest or @v/list go through the latest handler.
	if version != "" {
		return d.proxyGoExplicitVersion(c, ctx, span, golang, configs, requestPath)
	}
	return d.proxyGoLatest(c, ctx, span, golang, configs, requestPath, packageName)
}

// proxyGoExplicitVersion handles Go proxy requests for a specific version (.info, .mod, .zip).
func (d *GoDependencyProxyController) proxyGoExplicitVersion(c shared.Context, ctx context.Context, span trace.Span, eco ecosystem, configs DependencyProxyConfigs, requestPath string) error {
	cachePath, err := d.getCachePath(eco, requestPath)
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "go", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, eco, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "go", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, eco, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	if blocked, reason := d.checkMaliciousPackage(ctx, eco, requestPath); blocked {
		slog.Warn("Blocked malicious package", "proxy", "go", "path", requestPath, "reason", reason)
		if err := os.Remove(cachePath); err == nil {
			slog.Info("Removed malicious package from cache", "path", cachePath)
		}
		return d.blockMaliciousPackage(c, eco, requestPath, reason)
	}

	if eco.isCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "go", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			if d.VerifyCacheIntegrity(cachePath, data) {
				if configs.MinReleaseAge > 0 {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
							return d.blockTooNewPackage(c, eco, requestPath, releaseTime, configs.MinReleaseAge)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return eco.writeResponse(c, data, requestPath, true)
					}
					// No cached release time — fall through to upstream to retrieve it.
					slog.Debug("No cached release time for MinReleaseAge check, refetching", "proxy", "go", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return eco.writeResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "go", "path", requestPath)
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "go", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, eco, goProxyURL, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "go", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "go", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	_, releaseTime, hasReleaseTime := d.ExtractGoVersionAndReleaseTime(data)

	// Check MinReleaseAge for .info responses only — other file types don't carry timestamp data.
	if configs.MinReleaseAge > 0 && hasReleaseTime && strings.HasSuffix(requestPath, ".info") {
		if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, eco, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "go", "error", err)
	}

	// Store release time so MinReleaseAge can be enforced on future cache hits.
	if hasReleaseTime && strings.HasSuffix(requestPath, ".info") {
		if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
			slog.Warn("Failed to cache release time", "proxy", "go", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		c.Response().Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	return eco.writeResponse(c, data, requestPath, false)
}

// proxyGoLatest handles Go proxy requests for @latest and @v/list (version-resolution requests).
func (d *GoDependencyProxyController) proxyGoLatest(c shared.Context, ctx context.Context, span trace.Span, eco ecosystem, configs DependencyProxyConfigs, requestPath, packageName string) error {
	cachePath, err := d.getCachePath(eco, requestPath)
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "go", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Fetch from upstream — we need the response to resolve the version before we can check rules.
	data, headers, statusCode, err := d.fetchFromUpstream(ctx, eco, goProxyURL, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "go", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "go", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	resolvedVersion, releaseTime, hasReleaseTime := d.ExtractGoVersionAndReleaseTime(data)

	if resolvedVersion != "" {
		notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, eco, packageName+"@"+resolvedVersion, configs)
		if notAllowed {
			slog.Warn("Blocked not allowed package", "proxy", "go", "path", requestPath, "reason", notAllowedReason)
			return d.blockNotAllowedPackage(c, eco, requestPath, notAllowedReason)
		}

		slog.Debug("Checking resolved version for malicious package", "package", packageName, "version", resolvedVersion)
		isMalicious, entry, err := d.maliciousChecker.IsMalicious(ctx, eco.name(), packageName, resolvedVersion)
		if err != nil {
			slog.Error("Error checking malicious package", "proxy", "go", "error", err)
			return echo.NewHTTPError(500, "failed to check if package is malicious").WithInternal(err)
		}
		if isMalicious {
			reason := fmt.Sprintf("Package %s@%s is flagged as malicious (ID: %s)", packageName, resolvedVersion, entry.ID)
			if entry.Summary != "" {
				reason += ": " + entry.Summary
			}
			slog.Warn("Blocked malicious package after version resolution", "proxy", "go", "package", packageName, "version", resolvedVersion, "reason", reason)
			return d.blockMaliciousPackage(c, eco, requestPath, reason)
		}
	}

	if configs.MinReleaseAge > 0 && hasReleaseTime && resolvedVersion != "" {
		if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, eco, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "go", "error", err)
	}

	if hasReleaseTime && resolvedVersion != "" {
		if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
			slog.Warn("Failed to cache release time", "proxy", "go", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}
	if dockerContentDigest := headers.Get("Docker-Content-Digest"); dockerContentDigest != "" {
		c.Response().Header().Set("Docker-Content-Digest", dockerContentDigest)
	}

	return eco.writeResponse(c, data, requestPath, false)
}

// ExtractGoVersionAndReleaseTime parses a Go proxy .info response and returns the resolved version and its release time.
func (d *GoDependencyProxyController) ExtractGoVersionAndReleaseTime(data []byte) (string, time.Time, bool) {
	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Time.IsZero() {
		return "", time.Time{}, false
	}
	return info.Version, info.Time, true
}
