package dependencyfirewall

import (
	"context"
	"encoding/json"
	"fmt"
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

const composerMetadataRegistry = "https://repo.packagist.org"

var composerDistHosts = []string{
	"api.github.com", "codeload.github.com",
	"gitlab.com", "bitbucket.org", "repo.packagist.org",
}

type composerRootResponse struct {
	MetadataURL              string   `json:"metadata-url"`
	AvailablePackagePatterns []string `json:"available-package-patterns"`
}

type composerP2Document struct {
	Packages map[string][]json.RawMessage `json:"packages"`
	Minified string                       `json:"minified"`
}

func expandComposerVersions(entries []json.RawMessage, minified string) ([]json.RawMessage, error) {
	if minified != "composer/2.0" {
		return entries, nil
	}

	expanded := make([]json.RawMessage, 0, len(entries))
	current := map[string]json.RawMessage{}
	for _, entry := range entries {
		var diff map[string]json.RawMessage
		if err := json.Unmarshal(entry, &diff); err != nil {
			return nil, err
		}
		for key, value := range diff {
			if string(value) == `"__unset"` {
				delete(current, key)
			} else {
				current[key] = value
			}
		}
		full, err := json.Marshal(current)
		if err != nil {
			return nil, err
		}
		expanded = append(expanded, full)
	}
	return expanded, nil
}

var composerProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?composer(?:/|$)`)

// ComposerDependencyProxyController handles php dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type ComposerDependencyProxyController struct {
	*DependencyProxyController
}

func NewComposerDependencyProxyController(controller *DependencyProxyController) *ComposerDependencyProxyController {
	return &ComposerDependencyProxyController{DependencyProxyController: controller}
}

type composerEcosystem struct{}

var _ ecosystem = composerEcosystem{}

var composer composerEcosystem

func (composerEcosystem) name() string { return "composer" }

func (composerEcosystem) trimPrefix(path string) string {
	return strings.TrimSuffix(trimWithRegex(path, composerProxyPrefixRe), "/")
}

func isComposerPackageName(name string) bool {
	vendor, pkg, ok := strings.Cut(name, "/")
	return ok && vendor != "" && pkg != "" && !strings.Contains(pkg, "/")
}

func (composerEcosystem) parsePackage(path string) (string, string) {
	path = strings.Trim(path, "/")
	if rest, ok := strings.CutPrefix(path, "p2/"); ok {
		name := strings.TrimSuffix(rest, ".json")
		name = strings.TrimSuffix(name, "~dev")
		if isComposerPackageName(name) {
			return name, ""
		}
	}

	if rest, ok := strings.CutPrefix(path, "dist/"); ok {
		rest = strings.TrimSuffix(rest, ".zip")
		if index := strings.LastIndex(rest, "/"); index != -1 {
			if name, version := rest[:index], rest[index+1:]; isComposerPackageName(name) && version != "" {
				return name, version
			}
		}
	}

	return "", ""
}

func (composerEcosystem) packageIdentifier(packageName, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:composer/%s@%s", packageName, version)
	}
	return fmt.Sprintf("pkg:composer/%s", packageName)
}

func (composerEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "application/json"
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

	c.Response().Header().Set("X-Proxy-Type", "composer")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

// ProxyComposer dispatches a request to the root, metadata or dist handler. All three
// kinds of request live in the same path tree, so they cannot be told apart by route.
// @Summary Proxy Composer repository request
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/composer/{path} [get]
// @Router /dependency-proxy/{secret}/composer/{path} [get]
func (d *ComposerDependencyProxyController) ProxyComposer(c shared.Context) error {
	path := composer.trimPrefix(c.Request().URL.Path)

	switch {
	case strings.HasPrefix(path, "dist/"):
		return d.proxyComposerDist(c)
	case strings.HasPrefix(path, "p2/"):
		return d.proxyComposerMetadata(c)
	default:
		return d.proxyComposerRoot(c)
	}
}

func (d *ComposerDependencyProxyController) proxyComposerRoot(c shared.Context) error {
	if err := ensureReadMethod(c); err != nil {
		return err
	}

	path := strings.TrimSuffix(c.Request().URL.Path, "/")

	if !strings.HasSuffix(path, "packages.json") {
		return echo.NewHTTPError(http.StatusNotFound, "Failed to find status")
	}
	path = strings.TrimSuffix(path, "packages.json")
	path = path + "p2/%package%.json"

	return c.JSON(http.StatusOK, composerRootResponse{MetadataURL: path, AvailablePackagePatterns: []string{"*/*"}})
}

func (d *ComposerDependencyProxyController) proxyComposerDist(c shared.Context) error {
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

	requestPath := composer.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.composer",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "composer"),
			attribute.String("proxy.type", "dist"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	cacheKey := "composer/" + requestPath
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "composer", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, composer, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "composer", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, composer, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, version := composer.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, composer, packageName, version)
	if err != nil {
		return maliciousCheckFailed(composer, err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "composer", "path", requestPath, "status", status, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, composer, requestPath, reason, status)
	}

	if d.cache.Fresh(cacheKey, composerCacheTTL(requestPath)) {
		if entry, ok := d.cache.Get(cacheKey); ok {
			slog.Debug("Cache hit", "proxy", "composer", "path", requestPath)
			if configs.MinReleaseAge > 0 && time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
				return d.blockTooNewPackage(c, composer, requestPath, entry.releaseTime, configs.MinReleaseAge)
			}
			if entry.contentType != "" {
				c.Response().Header().Set("Content-Type", entry.contentType)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return composer.writeResponse(c, entry.data, requestPath, true)
		}
	}

	distURL, releaseTime, err := d.resolveComposerDist(ctx, packageName, version)
	if err != nil {
		span.RecordError(err)
		slog.Warn("Could not resolve dist url", "proxy", "composer", "package", packageName, "version", version, "error", err)
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("could not resolve %s@%s", packageName, version))
	}

	if err := checkComposerDistHost(distURL); err != nil {
		span.RecordError(err)
		slog.Warn("Blocked dist url", "proxy", "composer", "package", packageName, "version", version, "url", distURL, "error", err)
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}

	if configs.MinReleaseAge > 0 {
		if releaseTime.IsZero() {
			slog.Warn("Could not determine release time", "proxy", "composer", "package", packageName, "version", version)
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("could not determine release time of %s@%s", packageName, version))
		}
		if time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
			return d.blockTooNewPackage(c, composer, requestPath, releaseTime, configs.MinReleaseAge)
		}
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, composer, distURL, "", c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "composer", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "composer", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if !releaseTime.IsZero() {
		if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime, contentType: headers.Get("Content-Type")}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "composer", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	return composer.writeResponse(c, data, requestPath, false)
}

func (d *ComposerDependencyProxyController) proxyComposerMetadata(c shared.Context) error {
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

	requestPath := composer.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.composer",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "composer"),
			attribute.String("proxy.type", "metadata"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	packageName, version := composer.parsePackage(requestPath)

	notAllowed, reason := d.CheckNotAllowedPackage(ctx, composer, requestPath, configs)
	if notAllowed {
		return d.blockNotAllowedPackage(c, composer, requestPath, reason)
	}

	status, reason, err := d.checkMalicious(ctx, composer, packageName, version)
	if err != nil {
		return maliciousCheckFailed(composer, err)
	}
	if status != 0 {
		return d.blockMaliciousPackage(c, composer, requestPath, reason, status)
	}

	data, headers, statusCode, err := d.fetchFromUpstream(
		ctx, composer, composerMetadataRegistry, requestPath, c.Request().Header, nil,
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "composer", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}
	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "composer", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	filtered, removed, err := filterComposerMetadata(data, composerProxyBaseURL(c),
		time.Duration(configs.MinReleaseAge)*time.Hour,
		func(v string) bool {
			blocked, _ := matchRules(composer.packageIdentifier(packageName, v), configs.Rules)
			return !blocked
		},
	)
	if err != nil {
		span.RecordError(err)
		slog.Error("Could not rewrite composer metadata", "proxy", "composer", "package", packageName, "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "upstream returned unexpected metadata")
	}
	if removed > 0 {
		slog.Info("Filtered composer version list", "proxy", "composer", "package", packageName, "removedVersions", removed)
		span.SetAttributes(attribute.Int("proxy.filtered_versions", removed))
	}

	return composer.writeResponse(c, filtered, requestPath, false)
}

func composerProxyBaseURL(c shared.Context) string {
	registryURL := os.Getenv("DEPENDENCY_PROXY_BASE_URL")
	if registryURL == "" {
		registryURL = "https://api.main.devguard.org/api/v1/dependency-proxy"
	}
	origin := strings.TrimSuffix(strings.TrimSuffix(registryURL, "/"), "/api/v1/dependency-proxy")

	composerPath := composerProxyPrefixRe.FindString(c.Request().URL.Path)
	if !strings.HasSuffix(composerPath, "/") {
		composerPath += "/"
	}

	return origin + composerPath
}

func filterComposerMetadata(data []byte, proxyBaseURL string, minAge time.Duration, allowed func(version string) bool) ([]byte, int, error) {
	var doc composerP2Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("could not decode composer metadata: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("could not decode composer metadata: %w", err)
	}

	removed := 0
	for name, minifiedEntries := range doc.Packages {
		entries, err := expandComposerVersions(minifiedEntries, doc.Minified)
		if err != nil {
			return nil, 0, fmt.Errorf("could not expand version entries of %s: %w", name, err)
		}
		kept := make([]json.RawMessage, 0, len(entries))

		for _, entry := range entries {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(entry, &fields); err != nil {
				return nil, 0, fmt.Errorf("could not decode version entry of %s: %w", name, err)
			}

			var version string
			if err := json.Unmarshal(fields["version"], &version); err != nil {
				return nil, 0, fmt.Errorf("could not decode version of %s: %w", name, err)
			}

			if !allowed(version) {
				removed++
				continue
			}

			var releasedAt string
			if err := json.Unmarshal(fields["time"], &releasedAt); err != nil {
				return nil, 0, fmt.Errorf("could not decode time of %s: %w", name, err)
			}

			released, err := time.Parse(time.RFC3339, releasedAt)
			if err != nil {
				return nil, 0, fmt.Errorf("could not parse time of %s@%s: %w", name, version, err)
			}

			if minAge > 0 && time.Since(released) < minAge {
				removed++
				continue
			}

			rawDist, ok := fields["dist"]
			if !ok {
				removed++
				continue
			}

			var dist map[string]json.RawMessage
			if err := json.Unmarshal(rawDist, &dist); err != nil {
				return nil, 0, fmt.Errorf("could not decode dist of %s@%s: %w", name, version, err)
			}

			newURL := fmt.Sprintf("%sdist/%s/%s.zip", proxyBaseURL, name, version)

			encodedURL, err := json.Marshal(newURL)
			if err != nil {
				return nil, 0, err
			}
			dist["url"] = encodedURL
			dist["type"] = json.RawMessage(`"zip"`)

			encodedDist, err := json.Marshal(dist)
			if err != nil {
				return nil, 0, err
			}
			fields["dist"] = encodedDist

			delete(fields, "source")

			rewritten, err := json.Marshal(fields)
			if err != nil {
				return nil, 0, err
			}
			kept = append(kept, rewritten)
		}

		doc.Packages[name] = kept
	}

	packages, err := json.Marshal(doc.Packages)
	if err != nil {
		return nil, 0, fmt.Errorf("could not encode composer metadata: %w", err)
	}
	raw["packages"] = packages
	delete(raw, "minified")

	out, err := json.Marshal(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("could not encode composer metadata: %w", err)
	}
	return out, removed, nil
}

func (d *ComposerDependencyProxyController) resolveComposerDist(ctx context.Context, packageName, version string) (string, time.Time, error) {
	metadataPath := fmt.Sprintf("p2/%s.json", packageName)

	data, _, statusCode, err := d.fetchFromUpstream(ctx, composer, composerMetadataRegistry, metadataPath, http.Header{}, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	if statusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("upstream returned status %d for %s", statusCode, metadataPath)
	}

	var doc composerP2Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", time.Time{}, fmt.Errorf("could not decode composer metadata: %w", err)
	}

	entries, err := expandComposerVersions(doc.Packages[packageName], doc.Minified)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("could not expand version entries of %s: %w", packageName, err)
	}

	for _, entry := range entries {
		var fields struct {
			Version string `json:"version"`
			Time    string `json:"time"`
			Dist    struct {
				URL string `json:"url"`
			} `json:"dist"`
		}
		if err := json.Unmarshal(entry, &fields); err != nil {
			return "", time.Time{}, fmt.Errorf("could not decode version entry of %s: %w", packageName, err)
		}
		if fields.Version != version {
			continue
		}
		if fields.Dist.URL == "" {
			return "", time.Time{}, fmt.Errorf("%s@%s has no dist url", packageName, version)
		}

		releaseTime, err := time.Parse(time.RFC3339, fields.Time)
		if err != nil {
			releaseTime = time.Time{}
		}
		return fields.Dist.URL, releaseTime, nil
	}

	return "", time.Time{}, fmt.Errorf("%s@%s not found upstream", packageName, version)
}

// checkComposerDistHost keeps a tampered or compromised upstream entry from turning this
// proxy into a fetcher for arbitrary hosts.
func checkComposerDistHost(distURL string) error {
	parsed, err := url.Parse(distURL)
	if err != nil {
		return fmt.Errorf("invalid dist url")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("dist url is not https")
	}
	for _, host := range composerDistHosts {
		if parsed.Hostname() == host {
			return nil
		}
	}
	return fmt.Errorf("dist host %s is not allowed", parsed.Hostname())
}

func composerCacheTTL(requestPath string) time.Duration {
	if strings.Contains(requestPath, ".zip") {
		return 168 * time.Hour // 7 days
	}
	return 1 * time.Hour
}
