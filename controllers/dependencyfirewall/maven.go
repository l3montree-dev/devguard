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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const mavenRegistry = "https://repo1.maven.org/maven2"

var (
	mavenProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?maven(?:/|$)`)
	mavenVersionDirRe  = regexp.MustCompile(`^\d[A-Za-z0-9._+-]*$|-SNAPSHOT$`)
)

// MavenDependencyProxyController handles Maven dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type MavenDependencyProxyController struct {
	*DependencyProxyController
}

func NewMavenDependencyProxyController(controller *DependencyProxyController) *MavenDependencyProxyController {
	return &MavenDependencyProxyController{DependencyProxyController: controller}
}

type mavenEcosystem struct{}

var maven mavenEcosystem

func (mavenEcosystem) name() string { return "maven" }

func (mavenEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, mavenProxyPrefixRe)
}

func (mavenEcosystem) parsePackage(path string) (string, string) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 || segments[0] == "" {
		return "", ""
	}

	if strings.HasPrefix(segments[len(segments)-1], "maven-metadata.xml") {
		segments = segments[:len(segments)-1]
		version := ""
		if len(segments) > 2 && mavenVersionDirRe.MatchString(segments[len(segments)-1]) {
			version = segments[len(segments)-1]
			segments = segments[:len(segments)-1]
		}
		if len(segments) < 2 {
			return "", ""
		}
		return mavenCoordinates(segments), version
	}

	if len(segments) < 4 {
		return "", ""
	}
	return mavenCoordinates(segments[:len(segments)-2]), segments[len(segments)-2]
}

func mavenCoordinates(segments []string) string {
	return strings.Join(segments[:len(segments)-1], ".") + "/" + segments[len(segments)-1]
}

func (mavenEcosystem) packageIdentifier(packageName, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:maven/%s@%s", packageName, version)
	}
	return fmt.Sprintf("pkg:maven/%s", packageName)
}

// mavenCacheTTL returns how long a cached maven package file stays fresh.
// Package archives are effectively immutable once published, so they get a
// long TTL; everything else gets a short one.
func mavenCacheTTL(requestPath string) time.Duration {
	if strings.Contains(requestPath, "maven-metadata.xml") || strings.Contains(requestPath, "-SNAPSHOT") {
		return 1 * time.Hour
	}
	return 168 * time.Hour // 7 days
}

func (mavenEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		c.Response().Header().Set("Content-Type", mavenContentType(path))
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "maven")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

func mavenContentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".sha1"), strings.HasSuffix(path, ".md5"),
		strings.HasSuffix(path, ".sha256"), strings.HasSuffix(path, ".sha512"),
		strings.HasSuffix(path, ".asc"):
		return "text/plain"
	case strings.HasSuffix(path, ".pom"), strings.HasSuffix(path, ".xml"):
		return "application/xml"
	case strings.HasSuffix(path, ".jar"), strings.HasSuffix(path, ".war"),
		strings.HasSuffix(path, ".aar"), strings.HasSuffix(path, ".ear"):
		return "application/java-archive"
	default:
		return "application/octet-stream"
	}
}

// ProxyMaven dispatches a request to the metadata or the artifact handler. Both kinds
// of request live in the same path tree, so they cannot be told apart by route.
// @Summary Proxy Maven repository request
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/maven/{path} [get]
// @Router /dependency-proxy/{secret}/maven/{path} [get]
func (d *MavenDependencyProxyController) ProxyMaven(c shared.Context) error {
	if strings.Contains(c.Request().URL.Path, "maven-metadata.xml") {
		return d.proxyMavenMetadata(c)
	}
	return d.proxyMavenPackage(c)
}

// proxyMavenPackage handles explicit-version Maven package downloads.
func (d *MavenDependencyProxyController) proxyMavenPackage(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	requestPath := maven.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.maven",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "maven"),
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

	slog.Info("Proxy request", "proxy", "maven", "type", "package", "method", c.Request().Method, "path", requestPath)

	cacheKey := "maven/" + requestPath
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "maven", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, maven, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "maven", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, maven, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	if blocked, reason := d.checkMaliciousPackage(ctx, maven, requestPath); blocked {
		slog.Warn("Blocked malicious package", "proxy", "maven", "path", requestPath, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, maven, requestPath, reason, http.StatusForbidden)
	}

	if d.cache.Fresh(cacheKey, mavenCacheTTL(requestPath)) {
		if entry, ok := d.cache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "maven", "path", requestPath)
			if configs.MinReleaseAge > 0 {
				if !entry.releaseTime.IsZero() {
					if time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
						return d.blockTooNewPackage(c, maven, requestPath, entry.releaseTime, configs.MinReleaseAge)
					}
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return maven.writeResponse(c, entry.data, requestPath, true)
				}
				// No cached release time
				slog.Debug("No cached release time for MinReleaseAge check, refetching", "proxy", "maven", "path", requestPath)
			} else {
				span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
				return maven.writeResponse(c, entry.data, requestPath, true)
			}
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchMavenFromUpstream(ctx, requestPath, c.Request().Header)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "maven", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "maven", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	releaseTime := mavenReleaseTime(headers)
	if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime}); err != nil {
		slog.Warn("Failed to cache response", "proxy", "maven", "error", err)
	}

	if configs.MinReleaseAge > 0 {
		if releaseTime.IsZero() {
			slog.Warn("Upstream did not provide a release time, skipping MinReleaseAge check", "proxy", "maven", "path", requestPath)
		} else if time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, maven, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return maven.writeResponse(c, data, requestPath, false)
}

// mavenReleaseTime reads the upload time of an artifact. Maven Central has no metadata
// API for this, so the Last-Modified header of the artifact itself is the only source.
func mavenReleaseTime(headers http.Header) time.Time {
	lastModified := headers.Get("Last-Modified")
	if lastModified == "" {
		return time.Time{}
	}
	t, err := http.ParseTime(lastModified)
	if err != nil {
		slog.Debug("Could not parse Last-Modified header", "proxy", "maven", "value", lastModified, "error", err)
		return time.Time{}
	}
	return t
}

func (d *MavenDependencyProxyController) fetchMavenFromUpstream(ctx context.Context, requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	requestPath = strings.TrimRight(requestPath, "/")
	url, err := url.JoinPath(mavenRegistry, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	slog.Debug("Fetching from upstream", "proxy", "maven", "url", url)

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

// proxyMavenMetadata handles maven-metadata.xml requests. The version list must not
// be served from cache, and no concrete version is known yet, so only rules and
// all-version malicious entries can be evaluated here.
func (d *MavenDependencyProxyController) proxyMavenMetadata(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	requestPath := maven.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.maven",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "maven"),
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

	slog.Info("Proxy request", "proxy", "maven", "type", "metadata", "method", c.Request().Method, "path", requestPath)

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, maven, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "maven", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, maven, requestPath, notAllowedReason)
	}

	packageName, version := maven.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, maven, packageName, version)
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "maven", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "maven", "package", packageName, "version", version, "reason", reason)
		return d.blockMaliciousPackage(c, maven, requestPath, reason, http.StatusForbidden)
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchMavenFromUpstream(ctx, requestPath, c.Request().Header)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "maven", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "maven", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return maven.writeResponse(c, data, requestPath, false)
}
