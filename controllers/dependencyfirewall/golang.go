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
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/packagerules"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/mod/semver"
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
	return strings.TrimRight(trimWithRegex(path, goProxyPrefixRe), "/")
}

func (goEcosystem) MatchesVersion(comp models.MaliciousAffectedComponent, version string) bool {
	return semverMatchesVersion(comp, version)
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

func (goEcosystem) packageIdentifier(packageName, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:go/%s@%s", packageName, version)
	}
	return fmt.Sprintf("pkg:go/%s", packageName)
}

// goCacheTTL returns how long a cached Go proxy response stays fresh.
// Explicit-version files (.info/.mod/.zip under /@v/) are immutable once
// published; everything else (e.g. @latest resolution) needs a shorter TTL.
func goCacheTTL(requestPath string) time.Duration {
	if strings.Contains(requestPath, "/@v/") {
		return 168 * time.Hour // 7 days
	}
	return 1 * time.Hour
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

func goPackage(module, version string, releasedAt time.Time) packagerules.Package {
	return packagerules.Package{Name: module, Version: version, Ecosystem: "golang", Purl: golang.packageIdentifier(module, version), ReleasedAt: releasedAt, Registry: goProxyURL}
}

// @Summary Proxy Go module requests
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/go [get]
// @Router /dependency-proxy/go/{path} [get]
// @Router /dependency-proxy/{secret}/go [get]
// @Router /dependency-proxy/{secret}/go/{path} [get]
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

	// Checksum database requests (GOSUMDB via the proxy) carry no module contents.
	if strings.HasPrefix(requestPath, "sumdb/") {
		return d.proxyGoSumDB(c, ctx, span, requestPath)
	}

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
	cacheKey := "go/" + requestPath
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "go", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	blocked, reason, err := d.checkMaliciousPackage(ctx, eco, requestPath)
	if err != nil {
		return maliciousCheckFailed(eco, err)
	}
	if blocked {
		slog.Warn("Blocked malicious package", "proxy", "go", "path", requestPath, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, eco, requestPath, reason, http.StatusForbidden)
	}

	moduleName, version := golang.parsePackage(requestPath)
	releaseTime, err := d.fetchGoReleaseTime(ctx, moduleName, version)
	if err != nil {
		slog.Warn("Could not determine release time", "proxy", "go", "module", moduleName, "version", version, "error", err)
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(goPackage(moduleName, version, releaseTime), configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "go", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, eco, requestPath, notAllowedReason)
	}

	if !bypassCache(c.Request()) && d.cache.Fresh(cacheKey, goCacheTTL(requestPath)) {
		if entry, ok := d.cache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "go", "path", requestPath)
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return eco.writeResponse(c, entry.data, requestPath, true)
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

	if !releaseTime.IsZero() {
		if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "go", "error", err)
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
	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Package-level check first (like the npm metadata request): modules flagged as
	// malicious in all versions are blocked before anything is resolved.
	status, reason, err := d.checkMalicious(ctx, eco, packageName, "")
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "go", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "go", "path", requestPath, "reason", reason)
		return d.blockMaliciousPackage(c, eco, requestPath, reason, status)
	}

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

	// Hide versions the explicit-version endpoint would reject anyway (too new or blocked
	// by a rule), so `go get` resolves to a version it can actually download.
	if strings.HasSuffix(requestPath, "/@v/list") && len(configs.Rules) > 0 {
		filtered, removed := filterGoVersionList(data, func(version string) bool {
			releaseTime, _ := d.fetchGoReleaseTime(ctx, packageName, version)
			blocked, _ := d.CheckNotAllowedPackage(goPackage(packageName, version, releaseTime), configs)
			return !blocked
		})
		if removed > 0 {
			slog.Info("Filtered go version list", "proxy", "go", "module", packageName, "removedVersions", removed)
			span.SetAttributes(attribute.Int("proxy.filtered_versions", removed))
		}
		data = filtered
	}

	resolvedVersion, releaseTime, _ := extractGoVersionAndReleaseTime(data)

	if resolvedVersion != "" {
		notAllowed, notAllowedReason := d.CheckNotAllowedPackage(goPackage(packageName, resolvedVersion, releaseTime), configs)
		if notAllowed {
			slog.Warn("Blocked not allowed package", "proxy", "go", "path", requestPath, "reason", notAllowedReason)
			return d.blockNotAllowedPackage(c, eco, requestPath, notAllowedReason)
		}

		status, reason, err := d.checkMalicious(ctx, eco, packageName, resolvedVersion)
		if err != nil {
			slog.Error("Error checking malicious package", "proxy", "go", "error", err)
			return echo.NewHTTPError(500, "failed to check if package is malicious").WithInternal(err)
		}
		if status != 0 {
			slog.Warn("Blocked malicious package after version resolution", "proxy", "go", "package", packageName, "version", resolvedVersion, "reason", reason)
			return d.blockMaliciousPackage(c, eco, requestPath, reason, http.StatusForbidden)
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

// proxyGoSumDB passes checksum database requests (sumdb/<name>/supported, /lookup, /tile)
// through to upstream. They carry no module contents, so no firewall checks apply.
func (d *GoDependencyProxyController) proxyGoSumDB(c shared.Context, ctx context.Context, span trace.Span, requestPath string) error {
	span.SetAttributes(attribute.String("proxy.type", "sumdb"))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, golang, goProxyURL, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "go", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	return d.passthroughUpstreamResponse(c, headers, statusCode, data)
}

// fetchGoReleaseTime returns the release time of module@version from the version's .info
// file, preferring the cached copy. A fetched .info is cached as well, so the explicit
// .info request and the version list filtering share it.
func (d *GoDependencyProxyController) fetchGoReleaseTime(ctx context.Context, moduleName, version string) (time.Time, error) {
	infoPath := moduleName + "/@v/" + version + ".info"
	cacheKey := "go/" + infoPath
	if entry, ok := d.cache.Get(cacheKey); ok && !entry.releaseTime.IsZero() {
		return entry.releaseTime, nil
	}

	data, _, statusCode, err := d.fetchFromUpstream(ctx, golang, goProxyURL, infoPath, http.Header{}, nil)
	if err != nil {
		return time.Time{}, err
	}
	if statusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("upstream returned status %d for %s", statusCode, infoPath)
	}
	_, releaseTime, ok := extractGoVersionAndReleaseTime(data)
	if !ok {
		return time.Time{}, fmt.Errorf("no release time in %s", infoPath)
	}
	if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime}); err != nil {
		slog.Warn("Failed to cache response", "proxy", "go", "error", err)
	}
	return releaseTime, nil
}

// filterGoVersionList filters an @v/list response (one version per line). Versions are
// checked from the highest semver downwards until the first allowed one: that is the
// version `go get` resolves to.
func filterGoVersionList(data []byte, allowed func(version string) bool) ([]byte, int) {
	var versions []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			versions = append(versions, v)
		}
	}

	keep := make(map[string]bool, len(versions))
	for _, v := range versions {
		keep[v] = true
	}

	sorted := slices.Clone(versions)
	slices.SortFunc(sorted, func(a, b string) int { return semver.Compare(b, a) })
	for _, v := range sorted {
		if allowed(v) {
			break
		}
		delete(keep, v)
	}

	out := make([]string, 0, len(keep))
	for _, v := range versions {
		if keep[v] {
			out = append(out, v)
		}
	}
	removed := len(versions) - len(out)
	if len(out) == 0 {
		return []byte{}, removed
	}
	return []byte(strings.Join(out, "\n") + "\n"), removed
}

// extractGoVersionAndReleaseTime parses a Go proxy .info response and returns the resolved version and its release time.
func extractGoVersionAndReleaseTime(data []byte) (string, time.Time, bool) {
	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Time.IsZero() {
		return "", time.Time{}, false
	}
	return info.Version, info.Time, true
}
