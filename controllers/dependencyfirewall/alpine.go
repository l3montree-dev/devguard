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
	"path"
	"regexp"
	"strings"
	"time"

	apk "github.com/knqyf263/go-apk-version"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	alpineRegistry = "https://dl-cdn.alpinelinux.org"
	alpineCacheTTL = 168 * time.Hour
)

var alpineProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/[^/]+/apk(?:/|$)`)

type AlpineDependencyProxyController struct {
	*DependencyProxyController
	alpineIndexes         *utils.LoadingCache[*alpineIndex]
	alpineUpstreamIndexes *utils.LoadingCache[*alpineUpstreamIndex]
}

func NewAlpineDependencyProxyController(controller *DependencyProxyController) *AlpineDependencyProxyController {
	return &AlpineDependencyProxyController{
		DependencyProxyController: controller,
		alpineIndexes:             utils.NewLoadingCache(alpineIndexTTL, alpineIndexMaxBytes, func(idx *alpineIndex) int { return idx.size }),
		alpineUpstreamIndexes:     utils.NewLoadingCache(alpineIndexTTL, alpineIndexMaxBytes, func(idx *alpineUpstreamIndex) int { return idx.size }),
	}
}

type alpineEcosystem struct{}

var alpine alpineEcosystem

var _ ecosystem = alpineEcosystem{}

func (alpineEcosystem) name() string { return "apk" }

func (alpineEcosystem) trimPrefix(path string) string {
	return strings.TrimSuffix(trimWithRegex(path, alpineProxyPrefixRe), "/")
}

func (alpineEcosystem) parsePackage(path string) (string, string) {
	if !strings.HasSuffix(path, ".apk") {
		return "", ""
	}
	fileName := strings.TrimSuffix(path, ".apk")

	segments := strings.Split(fileName, "/")

	versionSegments := strings.Split(segments[len(segments)-1], "-")
	if len(versionSegments) <= 2 {
		return "", ""
	}

	version := versionSegments[len(versionSegments)-2] + "-" + versionSegments[len(versionSegments)-1]

	packageName := strings.Join(versionSegments[:len(versionSegments)-2], "-")

	if packageName == "" || version == "" {
		return "", ""
	}

	return "alpine/" + packageName, version
}

func (alpineEcosystem) packageIdentifier(packageName, pkgVersion string) string {
	if pkgVersion != "" {
		return fmt.Sprintf("pkg:apk/%s@%s", packageName, pkgVersion)
	}
	return fmt.Sprintf("pkg:apk/%s", packageName)
}

func (alpineEcosystem) MatchesVersion(comp models.MaliciousAffectedComponent, v string) bool {
	if comp.AffectsAllVersions() {
		return true
	}

	requested, err := apk.NewVersion(v)
	if err != nil {
		return true
	}

	if comp.Version != nil {
		stored, err := apk.NewVersion(*comp.Version)
		if err != nil {
			return true
		}
		return requested.Compare(stored) == 0
	}

	if comp.VersionIntroduced != nil {
		introduced, err := apk.NewVersion(*comp.VersionIntroduced)
		if err != nil {
			return true
		}
		if requested.Compare(introduced) < 0 {
			return false
		}
	}

	if comp.VersionFixed != nil {
		fixed, err := apk.NewVersion(*comp.VersionFixed)
		if err != nil {
			return true
		}
		if requested.Compare(fixed) >= 0 {
			return false
		}
	}

	return true
}

func (alpineEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		c.Response().Header().Set("Content-Type", "application/octet-stream")
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", alpine.name())
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

// @Summary Proxy Alpine repository request
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @param secret path string true "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/{secret}/apk/{path} [get]
func (d *AlpineDependencyProxyController) ProxyAlpine(c shared.Context) error {
	// sanitized once - dispatch, package checks and the upstream fetch must all see the same path
	requestPath := alpine.trimPrefix(c.Request().URL.Path)
	if path.Base(requestPath) == "APKINDEX.tar.gz" {
		return d.proxyAlpineIndex(c, requestPath)
	}
	if isAlpineKeyName(path.Base(requestPath)) {
		return d.proxyAlpineKey(c, path.Base(requestPath))
	}
	if strings.HasSuffix(requestPath, ".apk") {
		return d.proxyAlpinePackage(c, requestPath)
	}
	return d.proxyAlpineMetadata(c, requestPath)
}

func (d *AlpineDependencyProxyController) proxyAlpineKey(c shared.Context, keyName string) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid").WithInternal(err)
	}

	rsaKey, err := d.alpineSigningKey(c.Request().Context(), configs.Secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load signing key").WithInternal(err)
	}
	currentName, err := alpineKeyName(&rsaKey.PublicKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to encode signing key").WithInternal(err)
	}
	// a stale name (e.g. from before a rotation) must not get the new key - apk would reject it anyway
	if keyName != currentName {
		return echo.NewHTTPError(http.StatusNotFound, "unknown signing key")
	}
	publicKey, err := alpinePublicKeyPEM(rsaKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to encode signing key").WithInternal(err)
	}
	return c.Blob(http.StatusOK, "application/x-pem-file", publicKey)
}

func (d *AlpineDependencyProxyController) proxyAlpineIndex(c shared.Context, requestPath string) error {
	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy."+alpine.name(),
		trace.WithAttributes(attribute.String("proxy.ecosystem", alpine.name()),
			attribute.String("proxy.type", "index"),
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
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	idx, err := d.getAlpineIndex(ctx, configs, path.Dir(requestPath))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error building alpine index", "proxy", alpine.name(), "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to build package index")
	}

	c.Response().Header().Set("Content-Type", "application/gzip")
	return alpine.writeResponse(c, idx.archive, requestPath, false)
}

func (d *AlpineDependencyProxyController) proxyAlpineMetadata(c shared.Context, requestPath string) error {

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy."+alpine.name(),
		trace.WithAttributes(attribute.String("proxy.ecosystem", alpine.name()),
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

	slog.Info("Proxy request", "proxy", alpine.name(), "type", "metadata", "method", c.Request().Method, "path", requestPath)

	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, alpine, configs.getRegistry(alpine, alpineRegistry), requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", alpine.name(), "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", alpine.name(), "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return alpine.writeResponse(c, data, requestPath, false)
}

func (d *AlpineDependencyProxyController) proxyAlpinePackage(c shared.Context, requestPath string) error {
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

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy."+alpine.name(),
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", alpine.name()),
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

	slog.Info("Proxy request", "proxy", alpine.name(), "type", "package", "method", c.Request().Method, "path", requestPath)

	cacheKey := "alpine/" + requestPath
	if err := secretCache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", alpine.name(), "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, pkgVersion := alpine.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, alpine, packageName, pkgVersion)
	if err != nil {
		return maliciousCheckFailed(alpine, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", alpine.name(), "path", requestPath, "status", status, "reason", reason)
		secretCache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, alpine, requestPath, reason, status)
	}

	registry := configs.getRegistry(alpine, alpineRegistry)

	if !bypassCache(c.Request()) && secretCache.Fresh(cacheKey, alpineCacheTTL) {
		if entry, ok := secretCache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", alpine.name(), "path", requestPath)
			notAllowed, notAllowedReason := d.CheckNotAllowedPackage(newPackage(alpine, registry, packageName, pkgVersion, entry.releaseTime), configs)
			if notAllowed {
				slog.Warn("Blocked not allowed package", "proxy", alpine.name(), "path", requestPath, "reason", notAllowedReason)
				return d.blockNotAllowedPackage(c, alpine, requestPath, notAllowedReason)
			}
			if entry.contentType != "" {
				c.Response().Header().Set("Content-Type", entry.contentType)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return alpine.writeResponse(c, entry.data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// the build time from the APKINDEX - Last-Modified only tells when the mirror wrote the file
	releaseTime, err := d.packageBuildTime(ctx, configs, requestPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error loading alpine package index", "proxy", alpine.name(), "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to load package index from upstream")
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, alpine, registry, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", alpine.name(), "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", alpine.name(), "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	ruleReleaseTime := releaseTime
	if ruleReleaseTime.IsZero() {
		// not listed in the index - counts as brand new, so min release age rules block instead of silently allowing
		ruleReleaseTime = time.Now()
	}
	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(newPackage(alpine, registry, packageName, pkgVersion, ruleReleaseTime), configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", alpine.name(), "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, alpine, requestPath, notAllowedReason)
	}

	if releaseTime.IsZero() {
		slog.Warn("Could not determine release time", "proxy", alpine.name(), "package", packageName, "version", pkgVersion)
	} else {
		if err := secretCache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
			slog.Warn("Failed to cache response", "proxy", alpine.name(), "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return alpine.writeResponse(c, data, requestPath, false)
}
