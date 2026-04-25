package dependencyfirewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

const npmRegistry = "https://registry.npmjs.org"

var npmProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?npm(?:/|$)`)

type npmEcosystem struct{}

var npm npmEcosystem

func (npmEcosystem) name() string { return "npm" }

func (npmEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, npmProxyPrefixRe)
}

func (npmEcosystem) parsePackage(path string) (string, string) {
	if strings.HasSuffix(path, ".tgz") {
		parts := strings.Split(path, "/-/")
		if len(parts) == 2 {
			pkgName := strings.TrimPrefix(parts[0], "/")
			filename := strings.TrimSuffix(parts[1], ".tgz")

			// Scoped packages (@babel/core) use just the package name as prefix; unscoped use the full name.
			var expectedPrefix string
			if strings.HasPrefix(pkgName, "@") {
				if idx := strings.LastIndex(pkgName, "/"); idx != -1 {
					expectedPrefix = pkgName[idx+1:]
				}
			} else {
				expectedPrefix = pkgName
			}

			version := strings.TrimPrefix(filename, expectedPrefix+"-")
			return pkgName, version
		}
	}
	pkgName := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/")
	return pkgName, ""
}

func (npmEcosystem) isCached(cachePath string) bool {
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

func (npmEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
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

// ProxyNPMTarball handles explicit-version npm requests (.tgz downloads).
// Routes: GET /npm/:package/-/* and GET /npm/:scope/:name/-/*
func (d *NPMDependencyProxyController) ProxyNPMTarball(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
	}

	requestPath := npm.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm"),
			attribute.String("proxy.type", "tarball"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	slog.Info("Proxy request", "proxy", "npm", "type", "tarball", "method", c.Request().Method, "path", requestPath)

	cachePath := d.getCachePath(npm, requestPath)

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, npm, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "npm", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, npm, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	if blocked, reason := d.checkMaliciousPackage(ctx, npm, requestPath); blocked {
		slog.Warn("Blocked malicious package", "proxy", "npm", "path", requestPath, "reason", reason)
		if err := os.Remove(cachePath); err == nil {
			slog.Info("Removed malicious package from cache", "path", cachePath)
		}
		return d.blockMaliciousPackage(c, npm, requestPath, reason)
	}

	if npm.isCached(cachePath) {
		slog.Debug("Cache hit", "proxy", "npm", "path", requestPath)
		data, err := os.ReadFile(cachePath)
		if err == nil {
			if d.VerifyCacheIntegrity(cachePath, data) {
				if configs.MinReleaseAge > 0 {
					if releaseTime, ok := d.ReadCachedReleaseTime(cachePath); ok {
						if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
							return d.blockTooNewPackage(c, npm, requestPath, releaseTime, configs.MinReleaseAge)
						}
						span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
						return npm.writeResponse(c, data, requestPath, true)
					}
					// No cached release time — fall through to upstream to retrieve it.
					slog.Debug("No cached release time for MinReleaseAge check, refetching", "proxy", "npm", "path", requestPath)
				} else {
					span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
					return npm.writeResponse(c, data, requestPath, true)
				}
			} else {
				slog.Warn("Cache integrity verification failed, refetching", "proxy", "npm", "path", requestPath)
				os.Remove(cachePath)
				os.Remove(cachePath + ".sha256")
			}
		} else {
			slog.Warn("Cache read error", "proxy", "npm", "error", err)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, npm, npmRegistry, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "npm", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	_, releaseTime := d.ExtractNPMVersionAndReleaseTimeFromMetadata(data)

	if configs.MinReleaseAge > 0 {
		if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, npm, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "npm", "error", err)
	}
	if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
		slog.Warn("Failed to cache release time", "proxy", "npm", "error", err)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return npm.writeResponse(c, data, requestPath, false)
}

// ProxyNPMMetadata handles metadata / version-resolution npm requests (no explicit version in path).
// Routes: GET /npm/:package and GET /npm/:scope/:name
func (d *NPMDependencyProxyController) ProxyNPMMetadata(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
	}

	requestPath := npm.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm"),
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

	slog.Info("Proxy request", "proxy", "npm", "type", "metadata", "method", c.Request().Method, "path", requestPath)

	cachePath := d.getCachePath(npm, requestPath)
	packageName, _ := npm.parsePackage(requestPath)

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Fetch from upstream — we need the metadata to resolve the version before we can check rules.
	data, headers, statusCode, err := d.fetchFromUpstream(ctx, npm, npmRegistry, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "npm", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	resolvedVersion, releaseTime := d.ExtractNPMVersionAndReleaseTimeFromMetadata(data)

	// Check allowlist before malicious DB to avoid false positives on explicitly allowed packages.
	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, npm, packageName+"@"+resolvedVersion, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "npm", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, npm, requestPath, notAllowedReason)
	}

	if resolvedVersion != "" {
		slog.Debug("Checking resolved version for malicious package", "package", packageName, "version", resolvedVersion)
		isMalicious, entry, err := d.maliciousChecker.IsMalicious(ctx, "npm", packageName, resolvedVersion)
		if err != nil {
			slog.Error("Error checking malicious package", "proxy", "npm", "error", err)
			return echo.NewHTTPError(500, "failed to check if package is malicious").WithInternal(err)
		}

		if isMalicious {
			reason := fmt.Sprintf("Package %s@%s is flagged as malicious (ID: %s)", packageName, resolvedVersion, entry.ID)
			if entry.Summary != "" {
				reason += ": " + entry.Summary
			}
			slog.Warn("Blocked malicious package after version resolution", "proxy", "npm", "package", packageName, "version", resolvedVersion, "reason", reason)
			return d.blockMaliciousPackage(c, npm, requestPath, reason)
		}
	}

	if configs.MinReleaseAge > 0 && packageName != "" {
		if time.Since(releaseTime) > time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, npm, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
		slog.Warn("Failed to cache response", "proxy", "npm", "error", err)
	}
	if err := d.CacheReleaseTime(cachePath, releaseTime); err != nil {
		slog.Warn("Failed to cache release time", "proxy", "npm", "error", err)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return npm.writeResponse(c, data, requestPath, false)
}

func (d *NPMDependencyProxyController) ProxyNPMAudit(c shared.Context) error {
	requestPath := npm.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm-audit",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm-audit"),
			attribute.String("proxy.path", requestPath),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy npm audit request", "method", c.Request().Method, "path", requestPath, "contentType", c.Request().Header.Get("Content-Type"))

	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		slog.Error("Error reading request body", "proxy", "npm-audit", "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}

	slog.Info("Forwarding npm audit request", "path", requestPath, "bodySize", len(bodyBytes), "body", string(bodyBytes)[:min(len(bodyBytes), 500)])

	data, headers, statusCode, err := d.fetchNPMAuditFromUpstream(ctx, requestPath, c.Request().Header, bodyBytes)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "npm-audit", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	return d.passthroughUpstreamResponse(c, headers, statusCode, data)
}

func (d *NPMDependencyProxyController) fetchNPMAuditFromUpstream(ctx context.Context, requestPath string, headers http.Header, bodyBytes []byte) ([]byte, http.Header, int, error) {
	requestPath = strings.TrimRight(requestPath, "/")
	url, err := url.JoinPath(npmRegistry, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	slog.Info("Fetching npm audit from upstream", "url", url, "bodySize", len(bodyBytes))

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.ContentLength = int64(len(bodyBytes))

	if contentEncoding := headers.Get("Content-Encoding"); contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
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

// ExtractNPMVersionAndReleaseTimeFromMetadata parses NPM package metadata JSON and extracts the latest version and its release time.
func (d *NPMDependencyProxyController) ExtractNPMVersionAndReleaseTimeFromMetadata(data []byte) (string, time.Time) {
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
