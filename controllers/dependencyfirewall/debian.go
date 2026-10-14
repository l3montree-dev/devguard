package dependencyfirewall

import (
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
	"pault.ag/go/debian/version"
)

const (
	debRegistry = "http://deb.debian.org"
	debCacheTTL = 168 * time.Hour
)

var debProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?deb(?:/|$)`)

// DEBDependencyProxyController handles debian dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type DebDependencyProxyController struct {
	*DependencyProxyController
}

func NewDebDependencyProxyController(controller *DependencyProxyController) *DebDependencyProxyController {
	return &DebDependencyProxyController{DependencyProxyController: controller}
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
// @Param secret path string false "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/deb/{path} [get]
// @Router /dependency-proxy/{secret}/deb/{path} [get]
func (d *DebDependencyProxyController) ProxyDeb(c shared.Context) error {
	if strings.HasSuffix(strings.TrimSuffix(c.Request().URL.Path, "/"), ".deb") {
		return d.proxyDebPackage(c)
	}
	return d.proxyDebMetadata(c)
}

func (d *DebDependencyProxyController) proxyDebMetadata(c shared.Context) error {
	if _, err := d.GetDependencyProxyConfigs(c); err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

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

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, deb, debRegistry, requestPath, c.Request().Header, nil)
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

func (d *DebDependencyProxyController) proxyDebPackage(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
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
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "deb", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, deb, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "deb", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, deb, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, pkgVersion := deb.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, deb, packageName, pkgVersion)
	if err != nil {
		return maliciousCheckFailed(deb, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "deb", "path", requestPath, "status", status, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, deb, requestPath, reason, status)
	}

	if !bypassCache(c.Request()) && d.cache.Fresh(cacheKey, debCacheTTL) {
		if entry, ok := d.cache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "deb", "path", requestPath)
			if configs.MinReleaseAge > 0 && time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
				return d.blockTooNewPackage(c, deb, requestPath, entry.releaseTime, configs.MinReleaseAge)
			}
			if entry.contentType != "" {
				c.Response().Header().Set("Content-Type", entry.contentType)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return deb.writeResponse(c, entry.data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, deb, debRegistry, requestPath, c.Request().Header, nil)
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

	releaseTime := debReleaseTime(headers)
	if releaseTime.IsZero() {
		slog.Warn("Could not determine release time", "proxy", "deb", "package", packageName, "version", pkgVersion)
		if configs.MinReleaseAge > 0 {
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("could not determine release time of %s@%s", packageName, pkgVersion))
		}
	} else {
		if configs.MinReleaseAge > 0 && time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, deb, requestPath, releaseTime, configs.MinReleaseAge)
		}
		if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
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
