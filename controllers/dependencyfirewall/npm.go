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
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const npmRegistry = "https://registry.npmjs.org"

var npmProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?npm(?:/|$)`)

// NPMDependencyProxyController handles npm dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type NPMDependencyProxyController struct {
	*DependencyProxyController
}

func NewNPMDependencyProxyController(controller *DependencyProxyController) *NPMDependencyProxyController {
	return &NPMDependencyProxyController{DependencyProxyController: controller}
}

type npmEcosystem struct{}

var npm npmEcosystem

func (npmEcosystem) name() string { return "npm" }

func (npmEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, npmProxyPrefixRe)
}

func (npmEcosystem) parsePackage(path string) (string, string) {
	// remove any trailing slash
	path = strings.TrimSuffix(path, "/")
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

func (npmEcosystem) packageIdentifier(packageName, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:npm/%s@%s", packageName, version)
	}
	return fmt.Sprintf("pkg:npm/%s", packageName)
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
// @Summary Proxy npm tarball download
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Param package path string false "npm package name"
// @Param scope path string false "npm scope"
// @Param name path string false "npm package name (scoped)"
// @Success 200 {file} binary
// @Router /dependency-proxy/npm/{package}/-/{path} [get]
// @Router /dependency-proxy/npm/{scope}/{name}/-/{path} [get]
// @Router /dependency-proxy/{secret}/npm/{package}/-/{path} [get]
// @Router /dependency-proxy/{secret}/npm/{scope}/{name}/-/{path} [get]
func (d *NPMDependencyProxyController) ProxyNPMTarball(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
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

	cacheKey := "npm/tarball/" + requestPath
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "npm", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, npm, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "npm", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, npm, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, version := npm.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, npm, packageName, version)
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "npm", "path", requestPath, "status", status, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, npm, requestPath, reason, status)
	}

	// Tarballs are immutable once published to npm, so a hash-verified hit
	// never needs a freshness check — it's valid forever. Tarballs are only
	// cached together with their release time, so it is always set here.
	if entry, ok := d.cache.Get(cacheKey); ok {
		slog.Debug("Cache hit", "proxy", "npm", "path", requestPath)
		if configs.MinReleaseAge > 0 && time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, npm, requestPath, entry.releaseTime, configs.MinReleaseAge)
		}
		span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
		return npm.writeResponse(c, entry.data, requestPath, true)
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

	// The tarball itself carries no publish date - it lives in the package metadata.
	// Always resolve it, even without MinReleaseAge: the cache is shared across proxy
	// secrets, so an entry stored for one config must be checkable under another.
	releaseTime, err := d.fetchNPMReleaseTime(ctx, packageName, version)
	if err != nil {
		slog.Warn("Could not determine release time", "proxy", "npm", "package", packageName, "version", version, "error", err)
		if configs.MinReleaseAge > 0 {
			// Fail closed: without a publish date the MinReleaseAge policy cannot be verified.
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("could not determine release time of %s@%s", packageName, version))
		}
	} else {
		if configs.MinReleaseAge > 0 && time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, npm, requestPath, releaseTime, configs.MinReleaseAge)
		}
		if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "npm", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return npm.writeResponse(c, data, requestPath, false)
}

type npmMetadataCacheEntry struct {
	data        []byte
	contentType string
}

// npmMetadata is a short-lived, size-bounded cache for npm package documents. A single
// `npm install` hits the same document for the metadata request and again for every
// tarball MinReleaseAge check; full documents can be several MB.
var npmMetadata = utils.NewTTLCache[string](5*time.Minute, 256*1024*1024, func(e npmMetadataCacheEntry) int {
	return len(e.data)
})

// fetchPackageMetadata returns the full (non-abbreviated) npm package document.
// Only successful responses are cached.
func (d *NPMDependencyProxyController) fetchPackageMetadata(ctx context.Context, packageName string) ([]byte, http.Header, int, error) {
	cacheKey := "npm/metadata/" + packageName
	if entry, ok := npmMetadata.Get(cacheKey); ok {
		slog.Debug("Cache hit for metadata", "proxy", "npm", "package", packageName)
		headers := http.Header{}
		headers.Set("Content-Type", entry.contentType)
		return entry.data, headers, http.StatusOK, nil
	}

	data, headers, status, err := d.fetchFromUpstream(ctx, npm, npmRegistry, "/"+packageName, nil, nil)
	if err != nil {
		return nil, nil, status, fmt.Errorf("failed to fetch metadata from upstream: %w", err)
	}
	if status == http.StatusOK {
		npmMetadata.Set(cacheKey, npmMetadataCacheEntry{data: data, contentType: headers.Get("Content-Type")})
	}
	return data, headers, status, nil
}

// fetchNPMReleaseTime returns the publish time of packageName@version from the package metadata.
func (d *NPMDependencyProxyController) fetchNPMReleaseTime(ctx context.Context, packageName, version string) (time.Time, error) {
	metadata, _, status, err := d.fetchPackageMetadata(ctx, packageName)
	if err != nil {
		return time.Time{}, err
	}
	if status != http.StatusOK {
		return time.Time{}, fmt.Errorf("upstream returned status %d for package metadata", status)
	}
	releaseTime, err := d.ExtractNPMReleaseTimeFromMetadata(metadata, version)
	if err != nil {
		return time.Time{}, err
	}
	if releaseTime.IsZero() {
		return time.Time{}, fmt.Errorf("no release time for version %s in package metadata", version)
	}
	return releaseTime, nil
}

// ProxyNPMMetadata handles metadata / version-resolution npm requests (no explicit version in path).
// Routes: GET /npm/:package and GET /npm/:scope/:name
// @Summary Proxy npm package metadata
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Param package path string false "npm package name"
// @Param scope path string false "npm scope"
// @Param name path string false "npm package name (scoped)"
// @Success 200 {object} map[string]interface{}
// @Router /dependency-proxy/npm/{package} [get]
// @Router /dependency-proxy/npm/{scope}/{name} [get]
// @Router /dependency-proxy/{secret}/npm/{package} [get]
// @Router /dependency-proxy/{secret}/npm/{scope}/{name} [get]
func (d *NPMDependencyProxyController) ProxyNPMMetadata(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
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

	packageName, _ := npm.parsePackage(requestPath)

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	status, reason, err := d.checkMalicious(ctx, npm, packageName, "")
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "npm", "path", requestPath, "status", status, "reason", reason)
		return d.blockMaliciousPackage(c, npm, requestPath, reason, status)
	}

	data, headers, statusCode, err := d.fetchPackageMetadata(ctx, packageName)
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

	// Hide versions the tarball endpoint would reject anyway (too new or blocked by a
	// rule), so the client resolves its semver range to a version it can actually install
	// instead of failing on the tarball download.
	if configs.MinReleaseAge > 0 || len(configs.Rules) > 0 {
		minAge := time.Duration(configs.MinReleaseAge) * time.Hour
		filtered, removed, err := FilterNPMMetadataVersions(data, func(version string, published time.Time) bool {
			if configs.MinReleaseAge > 0 && (published.IsZero() || time.Since(published) < minAge) {
				return false
			}
			blocked, _ := matchRules(npm.packageIdentifier(packageName, version), configs.Rules)
			return !blocked
		})
		if err != nil {
			return echo.NewHTTPError(http.StatusBadGateway, "Failed to parse package metadata from upstream").WithInternal(err)
		}
		if removed > 0 {
			slog.Info("Filtered npm metadata", "proxy", "npm", "package", packageName, "removedVersions", removed)
			span.SetAttributes(attribute.Int("proxy.filtered_versions", removed))
		}
		data = filtered
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return npm.writeResponse(c, data, requestPath, false)
}

// ProxyNPMRegistryAPI passes npm registry API requests (every path below /-/) through
// to upstream: audits (POST /-/npm/v1/security/advisories/bulk, /-/npm/v1/security/audits/quick),
// signing keys (GET /-/npm/v1/keys) and attestations (GET /-/npm/v1/attestations/<pkg>@<version>)
// used by `npm audit signatures`. These carry no package contents, so no firewall checks apply.
// @Summary Proxy npm registry API request
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Success 200 {object} map[string]interface{}
// @Router /dependency-proxy/npm/-/{path} [get]
// @Router /dependency-proxy/npm/-/{path} [post]
// @Router /dependency-proxy/{secret}/npm/-/{path} [get]
// @Router /dependency-proxy/{secret}/npm/-/{path} [post]
func (d *NPMDependencyProxyController) ProxyNPMRegistryAPI(c shared.Context) error {
	requestPath := npm.trimPrefix(c.Request().URL.Path)
	method := c.Request().Method

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.npm-registry-api",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "npm"),
			attribute.String("proxy.type", "registry-api"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	var body []byte
	switch method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		var err error
		body, err = io.ReadAll(c.Request().Body)
		if err != nil {
			slog.Error("Error reading request body", "proxy", "npm", "error", err)
			return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
		}
	default:
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "Method not allowed")
	}

	slog.Info("Proxy request", "proxy", "npm", "type", "registry-api", "method", method, "path", requestPath, "bodySize", len(body))

	data, headers, statusCode, err := d.fetchNPMRegistryAPIFromUpstream(ctx, method, requestPath, c.Request().URL.RawQuery, c.Request().Header, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "npm", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	return d.passthroughUpstreamResponse(c, headers, statusCode, data)
}

// fetchNPMRegistryAPIFromUpstream forwards a registry API request including the
// headers npm relies on (body encoding for audits, Accept for content negotiation).
func (d *NPMDependencyProxyController) fetchNPMRegistryAPIFromUpstream(ctx context.Context, method, requestPath, rawQuery string, headers http.Header, body []byte) ([]byte, http.Header, int, error) {
	requestPath = strings.TrimRight(requestPath, "/")
	upstreamURL, err := url.JoinPath(npmRegistry, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	if rawQuery != "" {
		upstreamURL += "?" + rawQuery
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, upstreamURL, bodyReader)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		if contentType := headers.Get("Content-Type"); contentType != "" {
			req.Header.Set("Content-Type", contentType)
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		if contentEncoding := headers.Get("Content-Encoding"); contentEncoding != "" {
			req.Header.Set("Content-Encoding", contentEncoding)
		}
		req.ContentLength = int64(len(body))
	}
	for _, name := range []string{"User-Agent", "Accept", "Accept-Encoding"} {
		if value := headers.Get(name); value != "" {
			req.Header.Set(name, value)
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

	if resp.StatusCode >= 400 {
		slog.Warn("Upstream error response", "proxy", "npm", "method", method, "url", upstreamURL, "statusCode", resp.StatusCode)
	}

	return data, resp.Header, resp.StatusCode, nil
}

// ExtractNPMReleaseTimeFromMetadata parses NPM package metadata JSON and returns the publish
// time of the given version. A zero time is returned when the version has no publish time.
func (d *NPMDependencyProxyController) ExtractNPMReleaseTimeFromMetadata(data []byte, version string) (time.Time, error) {
	var metadata struct {
		Time map[string]time.Time `json:"time"`
	}

	if err := json.Unmarshal(data, &metadata); err != nil {
		slog.Debug("Failed to parse NPM metadata", "error", err)
		return time.Time{}, err
	}

	return metadata.Time[version], nil
}

// FilterNPMMetadataVersions removes every version for which keep returns false from a full
// npm package document (versions + time) and repoints dist-tags that referenced a removed
// version: "latest" moves to the highest remaining stable version, other tags are dropped.
// All other fields are passed through untouched. It returns the rewritten document and the
// number of removed versions; when nothing is removed the original bytes are returned.
func FilterNPMMetadataVersions(data []byte, keep func(version string, published time.Time) bool) ([]byte, int, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("failed to parse npm metadata: %w", err)
	}

	var versions map[string]json.RawMessage
	if raw, ok := doc["versions"]; ok {
		if err := json.Unmarshal(raw, &versions); err != nil {
			return nil, 0, fmt.Errorf("failed to parse npm metadata versions: %w", err)
		}
	}
	var times map[string]json.RawMessage
	if raw, ok := doc["time"]; ok {
		if err := json.Unmarshal(raw, &times); err != nil {
			return nil, 0, fmt.Errorf("failed to parse npm metadata time: %w", err)
		}
	}

	removed := 0
	for version := range versions {
		var published time.Time
		if raw, ok := times[version]; ok {
			_ = json.Unmarshal(raw, &published) // unparsable time stays zero
		}
		if !keep(version, published) {
			delete(versions, version)
			delete(times, version)
			removed++
		}
	}
	if removed == 0 {
		return data, 0, nil
	}

	var distTags map[string]string
	if raw, ok := doc["dist-tags"]; ok {
		if err := json.Unmarshal(raw, &distTags); err != nil {
			return nil, 0, fmt.Errorf("failed to parse npm metadata dist-tags: %w", err)
		}
	}
	for tag, version := range distTags {
		if _, ok := versions[version]; ok {
			continue
		}
		delete(distTags, tag)
		if tag == "latest" {
			if replacement := highestStableNPMVersion(versions); replacement != "" {
				distTags[tag] = replacement
			}
		}
	}

	for key, value := range map[string]any{"versions": versions, "time": times, "dist-tags": distTags} {
		if _, ok := doc[key]; !ok {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, 0, err
		}
		doc[key] = raw
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, 0, err
	}
	return out, removed, nil
}

// highestStableNPMVersion returns the highest non-prerelease semver version, or "" if none exists.
func highestStableNPMVersion(versions map[string]json.RawMessage) string {
	var best *semver.Version
	bestRaw := ""
	for raw := range versions {
		v, err := semver.NewVersion(raw)
		if err != nil || v.Prerelease() != "" {
			continue
		}
		if best == nil || v.GreaterThan(best) {
			best, bestRaw = v, raw
		}
	}
	return bestRaw
}
