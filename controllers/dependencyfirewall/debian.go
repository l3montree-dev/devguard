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
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"pault.ag/go/debian/version"
)

const (
	debCacheTTL        = 168 * time.Hour
	debKeyringFile     = "devguard-deb-keyring.asc"
	debIndexRetryAfter = time.Hour
)

var debProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/[^/]+/deb(?:/|$)`)

// DEBDependencyProxyController handles debian dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type DebDependencyProxyController struct {
	*DependencyProxyController
	debIndexes            *utils.LoadingCache[*debIndex]
	debReleaseTimeService shared.DebReleaseTimeService
}

func NewDebDependencyProxyController(controller *DependencyProxyController, debReleaseTimeService shared.DebReleaseTimeService) *DebDependencyProxyController {
	return &DebDependencyProxyController{
		DependencyProxyController: controller,
		debIndexes:                utils.NewLoadingCache(debIndexTTL, debIndexMaxBytes, func(idx *debIndex) int { return idx.size }),
		debReleaseTimeService:     debReleaseTimeService,
	}
}

type debEcosystem struct{}

var deb debEcosystem

var _ ecosystem = debEcosystem{}

func (debEcosystem) name() string { return "deb" }

func (debEcosystem) trimPrefix(path string) string {
	return strings.TrimSuffix(trimWithRegex(path, debProxyPrefixRe), "/")
}

func (debEcosystem) parsePackage(path string) (string, string) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 || segments[0] == "" {
		return "", ""
	}

	if !strings.HasSuffix(segments[len(segments)-1], ".deb") {
		return "", ""
	}

	packageSegments := strings.Split(segments[len(segments)-1], "_")

	if len(packageSegments) != 3 {
		return "", ""
	}

	return "debian/" + packageSegments[0], packageSegments[1]
}

func (debEcosystem) packageIdentifier(packageName, pkgVersion string) string {
	if pkgVersion != "" {
		return fmt.Sprintf("pkg:deb/%s@%s", packageName, pkgVersion)
	}
	return fmt.Sprintf("pkg:deb/%s", packageName)
}

func (debEcosystem) MatchesVersion(comp models.MaliciousAffectedComponent, v string) bool {
	if comp.AffectsAllVersions() {
		return true
	}

	requested, err := version.Parse(v)
	if err != nil {
		return true
	}

	if comp.Version != nil {
		stored, err := version.Parse(*comp.Version)
		if err != nil {
			return true
		}
		return version.Compare(requested, stored) == 0
	}

	if comp.VersionIntroduced != nil {
		introduced, err := version.Parse(*comp.VersionIntroduced)
		if err != nil {
			return true
		}
		if version.Compare(requested, introduced) < 0 {
			return false
		}
	}

	if comp.VersionFixed != nil {
		fixed, err := version.Parse(*comp.VersionFixed)
		if err != nil {
			return true
		}
		if version.Compare(requested, fixed) >= 0 {
			return false
		}
	}

	return true
}

func (debEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "application/octet-stream"
		if strings.HasSuffix(path, ".deb") {
			contentType = "application/vnd.debian.binary-package"
		}
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "deb")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

// @Summary Proxy Debian repository request
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @param secret path string true "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/{secret}/deb/{path} [get]
func (d *DebDependencyProxyController) ProxyDeb(c shared.Context) error {
	path := strings.TrimSuffix(c.Request().URL.Path, "/")
	if strings.HasSuffix(path, ".deb") {
		return d.proxyDebPackage(c)
	}
	if strings.HasSuffix(path, "/"+debKeyringFile) {
		return d.proxyDebKeyring(c)
	}
	return d.proxyDebMetadata(c)
}

func (d *DebDependencyProxyController) proxyDebKeyring(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid").WithInternal(err)
	}

	_, publicKey, err := d.dependencyProxyService.GetOrCreateDebSigningKey(c.Request().Context(), configs.Secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load signing key").WithInternal(err)
	}
	return c.Blob(http.StatusOK, "application/pgp-keys", []byte(publicKey))
}

func (d *DebDependencyProxyController) proxyDebMetadata(c shared.Context) error {
	requestPath := deb.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.deb",
		trace.WithAttributes(attribute.String("proxy.ecosystem", "deb"),
			attribute.String("proxy.type", "metadata"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	slog.Info("Proxy request", "proxy", "deb", "type", "metadata", "method", c.Request().Method, "path", requestPath)

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	if archive, suite, rest, ok := parseDebDistPath(requestPath); ok {
		if configs.getRegistry(deb, shared.DebRegistry) == shared.DebRegistry && !shared.IsDebSuiteSupported(archive, suite) {
			return echo.NewHTTPError(http.StatusNotFound, "debian suite "+archive+"/"+suite+" is not supported")
		}
		idx, err := d.getDebIndex(ctx, configs, archive, suite)
		if shared.IsNotFound(err) {
			c.Response().Header().Set("Retry-After", strconv.Itoa(int(debIndexRetryAfter.Seconds())))
			return echo.NewHTTPError(http.StatusServiceUnavailable, "debian index has not been collected yet").WithInternal(err)
		}
		if err != nil {
			slog.Error("Error building debian index", "proxy", "deb", "error", err)
			return echo.NewHTTPError(http.StatusBadGateway, "failed to build debian index").WithInternal(err)
		}
		if data, ok := idx.lookup(rest); ok {
			return deb.writeResponse(c, data, requestPath, true)
		}
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, deb, configs.getRegistry(deb, shared.DebRegistry), requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "deb", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "deb", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return deb.writeResponse(c, data, requestPath, false)
}

func parseDebDistPath(path string) (archive, suite, rest string, ok bool) {
	archive, dist, found := strings.Cut(strings.Trim(path, "/"), "/dists/")
	if !found {
		return "", "", "", false
	}

	suite, rest, found = strings.Cut(dist, "/")
	if !found || archive == "" || suite == "" || rest == "" {
		return "", "", "", false
	}

	return archive, suite, rest, true
}

func (d *DebDependencyProxyController) proxyDebPackage(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	secretCache, err := d.caches.forSecret(configs.Secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load cache").WithInternal(err)
	}

	requestPath := deb.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.deb",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "deb"),
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

	slog.Info("Proxy request", "proxy", "deb", "type", "package", "method", c.Request().Method, "path", requestPath)

	cacheKey := "deb/" + requestPath
	if err := secretCache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "deb", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, pkgVersion := deb.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, deb, packageName, pkgVersion)
	if err != nil {
		return maliciousCheckFailed(deb, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "deb", "path", requestPath, "status", status, "reason", reason)
		secretCache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, deb, requestPath, reason, status)
	}

	registry := configs.getRegistry(deb, shared.DebRegistry)

	if !bypassCache(c.Request()) && secretCache.Fresh(cacheKey, debCacheTTL) {
		if entry, ok := secretCache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "deb", "path", requestPath)
			notAllowed, notAllowedReason := d.CheckNotAllowedPackage(newPackage(deb, registry, packageName, pkgVersion, entry.releaseTime), configs)
			if notAllowed {
				slog.Warn("Blocked not allowed package", "proxy", "deb", "path", requestPath, "reason", notAllowedReason)
				return d.blockNotAllowedPackage(c, deb, requestPath, notAllowedReason)
			}
			if entry.contentType != "" {
				c.Response().Header().Set("Content-Type", entry.contentType)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return deb.writeResponse(c, entry.data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	upstreamRegistry, upstreamPath := debUpstream(registry, requestPath)
	data, headers, statusCode, err := d.fetchFromUpstream(ctx, deb, upstreamRegistry, upstreamPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "deb", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "deb", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	releaseTime, ok := d.indexedReleaseTime(configs, requestPath)
	if !ok {
		releaseTime = debReleaseTime(headers)
	}
	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(newPackage(deb, registry, packageName, pkgVersion, releaseTime), configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "deb", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, deb, requestPath, notAllowedReason)
	}

	if releaseTime.IsZero() {
		slog.Warn("Could not determine release time", "proxy", "deb", "package", packageName, "version", pkgVersion)
	} else {
		if err := secretCache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "deb", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return deb.writeResponse(c, data, requestPath, false)
}

func debReleaseTime(headers http.Header) time.Time {
	lastModified := headers.Get("Last-Modified")
	if lastModified == "" {
		return time.Time{}
	}
	t, err := http.ParseTime(lastModified)
	if err != nil {
		slog.Debug("Could not parse Last-Modified header", "proxy", "deb", "value", lastModified, "error", err)
		return time.Time{}
	}
	return t
}
