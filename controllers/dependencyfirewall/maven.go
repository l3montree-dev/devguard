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
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
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

	mavenVersionsBlockRe = regexp.MustCompile(`(?s)<versions>(.*?)</versions>`)
	mavenVersionRe       = regexp.MustCompile(`<version>([^<]*)</version>`)
	mavenLatestRe        = regexp.MustCompile(`<latest>[^<]*</latest>`)
	mavenReleaseRe       = regexp.MustCompile(`<release>[^<]*</release>`)
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

var _ ecosystem = mavenEcosystem{}

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

func (mavenEcosystem) MatchesVersion(comp models.MaliciousAffectedComponent, version string) bool {
	return semverMatchesVersion(comp, version)
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

	orgCache, err := d.caches.forOrg(configs.OrgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load cache").WithInternal(err)
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
	if err := orgCache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "maven", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, maven, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "maven", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, maven, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, version := maven.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, maven, packageName, version)
	if err != nil {
		return maliciousCheckFailed(maven, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "maven", "path", requestPath, "status", status, "reason", reason)
		orgCache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, maven, requestPath, reason, status)
	}

	if !bypassCache(c.Request()) && orgCache.Fresh(cacheKey, mavenCacheTTL(requestPath)) {
		if entry, ok := orgCache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "maven", "path", requestPath)
			if configs.MinReleaseAge > 0 && time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
				return d.blockTooNewPackage(c, maven, requestPath, entry.releaseTime, configs.MinReleaseAge)
			}
			if entry.contentType != "" {
				c.Response().Header().Set("Content-Type", entry.contentType)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return maven.writeResponse(c, entry.data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, maven, mavenRegistry, requestPath, c.Request().Header, nil)
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
	if releaseTime.IsZero() {
		slog.Warn("Could not determine release time", "proxy", "maven", "package", packageName, "version", version)
		if configs.MinReleaseAge > 0 {
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("could not determine release time of %s@%s", packageName, version))
		}
	} else {
		if configs.MinReleaseAge > 0 && time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, maven, requestPath, releaseTime, configs.MinReleaseAge)
		}
		if err := orgCache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "maven", "error", err)
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

	orgCache, err := d.caches.forOrg(configs.OrgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load cache").WithInternal(err)
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

	packageName, version := maven.parsePackage(requestPath)

	if version != "" {
		notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, maven, requestPath, configs)
		if notAllowed {
			slog.Warn("Blocked not allowed package", "proxy", "maven", "path", requestPath, "reason", notAllowedReason)
			return d.blockNotAllowedPackage(c, maven, requestPath, notAllowedReason)
		}
	}

	status, reason, err := d.checkMalicious(ctx, maven, packageName, version)
	if err != nil {
		return maliciousCheckFailed(maven, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "maven", "package", packageName, "version", version, "reason", reason)
		return d.blockMaliciousPackage(c, maven, requestPath, reason, status)
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, maven, mavenRegistry, requestPath, c.Request().Header, nil)
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

	// Hide versions the explicit-version endpoint would reject anyway (too new or blocked
	// by a rule), so Maven resolves to a version it can actually download.
	if version == "" && (configs.MinReleaseAge > 0 || len(configs.Rules) > 0) {
		filtered, removed := filterMavenMetadata(data,
			time.Duration(configs.MinReleaseAge)*time.Hour,
			func(v string) (time.Time, error) { return d.fetchMavenReleaseTime(ctx, packageName, v, orgCache) },
			func(v string) bool {
				blocked, _ := matchRules(maven.packageIdentifier(packageName, v), configs.Rules)
				return !blocked
			},
		)
		if removed > 0 {
			slog.Info("Filtered maven version list", "proxy", "maven", "package", packageName, "removedVersions", removed)
			span.SetAttributes(attribute.Int("proxy.filtered_versions", removed))
		}
		data = filtered
	}

	return maven.writeResponse(c, data, requestPath, false)
}

// fetchMavenReleaseTime returns the publish time of packageName@version, preferring the
// cached copy. Maven Central has no metadata API for this, so the Last-Modified header of
// the version's POM is the only source. The POM is used rather than the JAR because it is
// small and always exists, even for pom-packaging artifacts. The cache key matches the one
// proxyMavenPackage uses, so a POM that was proxied normally is reused here.
func (d *MavenDependencyProxyController) fetchMavenReleaseTime(ctx context.Context, packageName, version string, orgCache *cache) (time.Time, error) {
	groupID, artifactID, ok := strings.Cut(packageName, "/")
	if !ok {
		return time.Time{}, fmt.Errorf("invalid maven coordinates %q", packageName)
	}
	pomPath := fmt.Sprintf("%s/%s/%s/%s-%s.pom",
		strings.ReplaceAll(groupID, ".", "/"), artifactID, version, artifactID, version)

	cacheKey := "maven/" + pomPath
	if entry, ok := orgCache.Get(cacheKey); ok && !entry.releaseTime.IsZero() {
		return entry.releaseTime, nil
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, maven, mavenRegistry, pomPath, http.Header{}, nil)
	if err != nil {
		return time.Time{}, err
	}
	if statusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("upstream returned status %d for %s", statusCode, pomPath)
	}
	releaseTime := mavenReleaseTime(headers)
	if releaseTime.IsZero() {
		return time.Time{}, fmt.Errorf("no Last-Modified header for %s", pomPath)
	}
	if err := orgCache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
		slog.Warn("Failed to cache response", "proxy", "maven", "error", err)
	}
	return releaseTime, nil
}

// filterMavenMetadata removes versions from a maven-metadata.xml document. Versions for
// which allowed returns false are dropped. With a minimum age, versions are checked from
// the newest downwards until the first one that is old enough - Maven Central appends new
// releases to the end of the list, so it is already in chronological order and no version
// comparison is needed. Older versions are kept without fetching their release time.
// <latest> and <release> are rewritten to the newest remaining version, so LATEST and
// RELEASE cannot resolve to a version the artifact endpoint would then block.
func filterMavenMetadata(data []byte, minAge time.Duration, releaseTime func(version string) (time.Time, error), allowed func(version string) bool) ([]byte, int) {
	block := mavenVersionsBlockRe.FindSubmatchIndex(data)
	if block == nil {
		return data, 0
	}

	var versions []string
	for _, m := range mavenVersionRe.FindAllSubmatch(data[block[2]:block[3]], -1) {
		versions = append(versions, string(m[1]))
	}

	keep := make(map[string]bool, len(versions))
	candidates := make([]string, 0, len(versions))
	for _, v := range versions {
		if allowed(v) {
			keep[v] = true
			candidates = append(candidates, v)
		}
	}

	if minAge > 0 {
		for i := len(candidates) - 1; i >= 0; i-- {
			t, err := releaseTime(candidates[i])
			if err == nil && time.Since(t) >= minAge {
				break
			}
			delete(keep, candidates[i])
		}
	}

	out := make([]string, 0, len(keep))
	for _, v := range versions {
		if keep[v] {
			out = append(out, v)
		}
	}
	removed := len(versions) - len(out)
	if removed == 0 {
		return data, 0
	}

	rebuilt := "<versions/>"
	if len(out) > 0 {
		rebuilt = "<versions>\n      <version>" +
			strings.Join(out, "</version>\n      <version>") +
			"</version>\n    </versions>"
	}
	result := make([]byte, 0, len(data))
	result = append(result, data[:block[0]]...)
	result = append(result, rebuilt...)
	result = append(result, data[block[1]:]...)

	if len(out) == 0 {
		result = mavenLatestRe.ReplaceAll(result, nil)
		result = mavenReleaseRe.ReplaceAll(result, nil)
	} else {
		newest := out[len(out)-1]
		result = mavenLatestRe.ReplaceAll(result, []byte("<latest>"+newest+"</latest>"))
		result = mavenReleaseRe.ReplaceAll(result, []byte("<release>"+newest+"</release>"))
	}
	return result, removed
}
