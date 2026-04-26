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
	"crypto/sha256"
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

var ociProxyPrefixRe = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?oci(?:/|$)`)

// OCIDependencyProxyController handles OCI registry proxy requests.
// Image references must be fully qualified: <registry>/<image> (e.g. docker.io/library/nginx).
// It embeds DependencyProxyController to reuse shared helpers and state.
type OCIDependencyProxyController struct {
	*DependencyProxyController
}

func NewOCIDependencyProxyController(controller *DependencyProxyController) *OCIDependencyProxyController {
	return &OCIDependencyProxyController{DependencyProxyController: controller}
}

type ociEcosystem struct{}

var ociEco ociEcosystem

func (ociEcosystem) name() string { return "oci" }

func (ociEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, ociProxyPrefixRe)
}

// parsePackage extracts the fully-qualified image name (registry/image) and
// the tag or digest from an OCI request path of the form /v2/<registry>/<image>/manifests/<ref>.
// The registry segment is included in the returned package name so rules can
// match on it (e.g. pkg:oci/docker.io/library/nginx@latest).
func (ociEcosystem) parsePackage(path string) (string, string) {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "v2/")
	path = strings.TrimPrefix(path, "/")

	if before, after, ok := strings.Cut(path, "/manifests/"); ok {
		return before, after
	}
	if before, after, ok := strings.Cut(path, "/blobs/"); ok {
		return before, after
	}
	if before, _, ok := strings.Cut(path, "/tags/list"); ok {
		return before, ""
	}
	return strings.TrimRight(path, "/"), ""
}

// packageIdentifier returns a plain image reference (registry/image:tag or registry/image@digest)
// so that OCI firewall rules can be written as docker.io/library/nginx:latest instead of PURLs.
func (ociEcosystem) packageIdentifier(packageName, version string) string {
	if version == "" {
		return packageName
	}
	if strings.HasPrefix(version, "sha256:") {
		return packageName + "@" + version
	}
	return packageName + ":" + version
}

func (ociEcosystem) isCached(cachePath string) bool {
	info, err := os.Stat(cachePath)
	if err != nil {
		return false
	}
	// Blobs are content-addressed and immutable.
	if strings.Contains(cachePath, "/blobs/") {
		return true
	}
	// Digest-pinned manifests are immutable.
	if strings.Contains(cachePath, "/manifests/sha256_") {
		return true
	}
	// Tag-based manifests: 1 hour TTL.
	return time.Since(info.ModTime()) < time.Hour
}

func (ociEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}
	c.Response().Header().Set("X-Proxy-Type", "oci")

	contentType := c.Response().Header().Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return c.Blob(http.StatusOK, contentType, data)
}

// ociSafeCachePath replaces colons in digest strings (sha256:abc) with underscores
// since colons are not safe in file names on all platforms (e.g. macOS).
func ociSafeCachePath(requestPath string) string {
	return strings.ReplaceAll(requestPath, ":", "_")
}

// upstreamURLForRegistry returns the upstream base URL for a given registry hostname.
// docker.io is a special case: its actual API endpoint differs from the pull hostname.
func upstreamURLForRegistry(registry string) string {
	if registry == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + registry
}

// imageParamsFromContext reconstructs the fully-qualified image name and the
// upstream request path from Echo route parameters.
//
// Handles 1-, 2-, and 3-segment image names:
//   - :registry/:image                  → docker.io/nginx
//   - :registry/:namespace/:image       → docker.io/library/nginx
//   - :registry/:ns1/:ns2/:image        → ghcr.io/org/team/repo
func imageParamsFromContext(c shared.Context) (registry, fqImageName, upstreamImagePath string) {
	registry = c.Param("registry")
	// 2-segment route uses :namespace; 3-segment route uses :ns1 + :ns2.
	namespace := c.Param("namespace")
	ns1 := c.Param("ns1")
	ns2 := c.Param("ns2")
	image := c.Param("image")

	switch {
	case ns1 != "" && ns2 != "":
		// 3-segment: :registry/:ns1/:ns2/:image
		upstreamImagePath = ns1 + "/" + ns2 + "/" + image
	case namespace != "":
		// 2-segment: :registry/:namespace/:image
		upstreamImagePath = namespace + "/" + image
	default:
		// 1-segment: :registry/:image
		upstreamImagePath = image
	}
	fqImageName = registry + "/" + upstreamImagePath
	return
}

type dockerTokenResponse struct {
	Token string `json:"token"`
}

// parseBearerChallenge extracts the realm, service and scope fields from a
// WWW-Authenticate: Bearer header value so token fetching works for any
// OCI-compliant registry without hardcoding auth URLs.
func parseBearerChallenge(header string) (realm, service, scope string) {
	header = strings.TrimPrefix(header, "Bearer ")
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			switch key {
			case "realm":
				realm = val
			case "service":
				service = val
			case "scope":
				scope = val
			}
		}
	}
	return
}

// fetchRegistryToken obtains an anonymous pull token by following the Bearer
// challenge advertised in the upstream 401 response.
// The realm URL is validated against the upstream registry host to prevent SSRF:
// a malicious registry could advertise realm="http://internal-host/" in its 401.
func (d *OCIDependencyProxyController) fetchRegistryToken(ctx context.Context, wwwAuthenticate string) (string, error) {
	realm, service, scope := parseBearerChallenge(wwwAuthenticate)
	if realm == "" {
		return "", fmt.Errorf("no realm in WWW-Authenticate header: %q", wwwAuthenticate)
	}

	params := url.Values{}
	if service != "" {
		params.Set("service", service)
	}
	if scope != "" {
		params.Set("scope", scope)
	}
	tokenURL := realm
	if len(params) > 0 {
		tokenURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp dockerTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	return tokenResp.Token, nil
}

// fetchOCIFromUpstream fetches an OCI resource from the given upstream registry,
// handling the Bearer token challenge transparently. Supports GET and HEAD.
//
// requestPath is the path sent to the upstream (without the registry segment),
// e.g. /v2/library/nginx/manifests/latest.
func (d *OCIDependencyProxyController) fetchOCIFromUpstream(ctx context.Context, method, upstreamBase, requestPath string) ([]byte, http.Header, int, error) {
	fullURL := upstreamBase + requestPath

	doRequest := func(token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Accept", strings.Join([]string{
			"application/vnd.docker.distribution.manifest.v2+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.oci.image.index.v1+json",
			"*/*",
		}, ","))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return d.client.Do(req)
	}

	resp, err := doRequest("")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to fetch: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("Www-Authenticate")
		resp.Body.Close()

		token, err := d.fetchRegistryToken(ctx, wwwAuth)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to get registry token: %w", err)
		}
		resp, err = doRequest(token)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to fetch with auth: %w", err)
		}
	}

	if method == http.MethodHead {
		resp.Body.Close()
		return nil, resp.Header, resp.StatusCode, nil
	}

	defer resp.Body.Close()
	// 10 GiB ceiling — large enough for any real OCI layer, prevents unbounded memory use.
	const maxResponseBytes = 10 << 30
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}
	return data, resp.Header, resp.StatusCode, nil
}

// ProxyOCIVersionCheck handles the OCI Distribution Spec v2 version check.
// Route: GET|HEAD /oci/v2/
func (d *OCIDependencyProxyController) ProxyOCIVersionCheck(c shared.Context) error {
	c.Response().Header().Set("Content-Type", "application/json")
	return c.JSON(http.StatusOK, map[string]string{})
}

// ProxyOCIManifest handles manifest fetch and existence-check requests.
// The registry hostname is part of the route so that requests are fully qualified:
//
//	docker.io/library/nginx:latest  →  GET /oci/v2/docker.io/library/nginx/manifests/latest
//	ghcr.io/org/image:sha256:abc    →  GET /oci/v2/ghcr.io/org/image/manifests/sha256:abc
//
// Routes:
//   - GET|HEAD /oci/v2/:registry/:image/manifests/:reference
//   - GET|HEAD /oci/v2/:registry/:namespace/:image/manifests/:reference
func (d *OCIDependencyProxyController) ProxyOCIManifest(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	registry, fqImageName, upstreamImagePath := imageParamsFromContext(c)
	reference := c.Param("reference")
	// Path sent to the upstream (no registry prefix).
	upstreamPath := fmt.Sprintf("/v2/%s/manifests/%s", upstreamImagePath, reference)
	// Path used for caching and rule matching (includes registry).
	requestPath := fmt.Sprintf("/v2/%s/manifests/%s", fqImageName, reference)
	method := c.Request().Method

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.oci",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "oci"),
			attribute.String("proxy.type", "manifest"),
			attribute.String("proxy.registry", registry),
			attribute.String("proxy.image", fqImageName),
			attribute.String("proxy.reference", reference),
			attribute.String("http.method", method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy request", "proxy", "oci", "type", "manifest", "method", method, "image", fqImageName, "reference", reference)

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, ociEco, requestPath, configs)
	if notAllowed {
		return d.blockNotAllowedPackage(c, ociEco, requestPath, notAllowedReason)
	}

	if blocked, reason := d.checkMaliciousPackage(ctx, ociEco, requestPath); blocked {
		return d.blockMaliciousPackage(c, ociEco, requestPath, reason)
	}

	cachePath, err := d.getCachePath(ociEco, ociSafeCachePath(requestPath))
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "oci", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid image path")
	}

	if method == http.MethodGet && ociEco.isCached(cachePath) {
		data, err := os.ReadFile(cachePath)
		if err == nil && d.VerifyCacheIntegrity(cachePath, data) {
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			if ct, err := os.ReadFile(cachePath + ".contenttype"); err == nil {
				c.Response().Header().Set("Content-Type", string(ct))
			}
			if digest, err := os.ReadFile(cachePath + ".digest"); err == nil {
				c.Response().Header().Set("Docker-Content-Digest", string(digest))
			}
			return ociEco.writeResponse(c, data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	upstreamBase := upstreamURLForRegistry(registry)
	data, headers, statusCode, err := d.fetchOCIFromUpstream(ctx, method, upstreamBase, upstreamPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching OCI manifest from upstream", "proxy", "oci", "error", err, "image", fqImageName)
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch from upstream registry")
	}

	if statusCode != http.StatusOK {
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if ct := headers.Get("Content-Type"); ct != "" {
		c.Response().Header().Set("Content-Type", ct)
	}
	if digest := headers.Get("Docker-Content-Digest"); digest != "" {
		c.Response().Header().Set("Docker-Content-Digest", digest)
	}

	if method == http.MethodGet && len(data) > 0 {
		if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
			slog.Warn("Failed to cache OCI manifest", "proxy", "oci", "error", err)
		}
		if ct := headers.Get("Content-Type"); ct != "" {
			if err := os.WriteFile(cachePath+".contenttype", []byte(ct), 0644); err != nil {
				slog.Warn("Failed to cache OCI manifest content-type", "proxy", "oci", "error", err)
			}
		}
		if digest := headers.Get("Docker-Content-Digest"); digest != "" {
			if err := os.WriteFile(cachePath+".digest", []byte(digest), 0644); err != nil {
				slog.Warn("Failed to cache OCI manifest digest", "proxy", "oci", "error", err)
			}
		}
	}

	if method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return ociEco.writeResponse(c, data, requestPath, false)
}

// ProxyOCIBlob handles layer and config blob downloads.
// Routes:
//   - GET|HEAD /oci/v2/:registry/:image/blobs/:digest
//   - GET|HEAD /oci/v2/:registry/:namespace/:image/blobs/:digest
func (d *OCIDependencyProxyController) ProxyOCIBlob(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	registry, fqImageName, upstreamImagePath := imageParamsFromContext(c)
	digest := c.Param("digest")
	upstreamPath := fmt.Sprintf("/v2/%s/blobs/%s", upstreamImagePath, digest)
	requestPath := fmt.Sprintf("/v2/%s/blobs/%s", fqImageName, digest)
	method := c.Request().Method

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.oci",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "oci"),
			attribute.String("proxy.type", "blob"),
			attribute.String("proxy.registry", registry),
			attribute.String("proxy.image", fqImageName),
			attribute.String("proxy.digest", digest),
			attribute.String("http.method", method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy request", "proxy", "oci", "type", "blob", "method", method, "image", fqImageName, "digest", digest)

	// Blobs are image-scoped; check the fully-qualified image name against rules.
	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, ociEco, fqImageName, configs)
	if notAllowed {
		return d.blockNotAllowedPackage(c, ociEco, requestPath, notAllowedReason)
	}

	cachePath, err := d.getCachePath(ociEco, ociSafeCachePath(requestPath))
	if err != nil {
		slog.Warn("Invalid cache path", "proxy", "oci", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid image path")
	}

	// Blobs are content-addressed and immutable; serve from cache unconditionally once present.
	if method == http.MethodGet && ociEco.isCached(cachePath) {
		data, err := os.ReadFile(cachePath)
		if err == nil && d.VerifyCacheIntegrity(cachePath, data) {
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			c.Response().Header().Set("Content-Type", "application/octet-stream")
			c.Response().Header().Set("Docker-Content-Digest", digest)
			return ociEco.writeResponse(c, data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	upstreamBase := upstreamURLForRegistry(registry)
	data, headers, statusCode, err := d.fetchOCIFromUpstream(ctx, method, upstreamBase, upstreamPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching OCI blob from upstream", "proxy", "oci", "error", err, "image", fqImageName)
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch from upstream registry")
	}

	if statusCode != http.StatusOK {
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if ct := headers.Get("Content-Type"); ct != "" {
		c.Response().Header().Set("Content-Type", ct)
	}
	if d := headers.Get("Docker-Content-Digest"); d != "" {
		c.Response().Header().Set("Docker-Content-Digest", d)
	}

	if method == http.MethodGet && len(data) > 0 {
		// Verify the downloaded content matches the requested digest before caching.
		// digest is of the form "sha256:<hex>"; skip verification for other algorithms.
		if algo, expected, ok := strings.Cut(digest, ":"); ok && algo == "sha256" {
			actual := fmt.Sprintf("%x", sha256.Sum256(data))
			if actual != expected {
				slog.Error("OCI blob digest mismatch", "proxy", "oci", "image", fqImageName, "expected", expected, "actual", actual)
				return echo.NewHTTPError(http.StatusBadGateway, "upstream blob digest mismatch")
			}
		}
		if err := d.CacheDataWithIntegrity(cachePath, data); err != nil {
			slog.Warn("Failed to cache OCI blob", "proxy", "oci", "error", err)
		}
	}

	if method == http.MethodHead {
		return c.NoContent(http.StatusOK)
	}
	return ociEco.writeResponse(c, data, requestPath, false)
}

// ProxyOCIReferrers handles the OCI referrers API (signatures, SBOMs, etc.).
// Routes:
//   - GET /v2/:registry/:image/referrers/:digest
//   - GET /v2/:registry/:namespace/:image/referrers/:digest
func (d *OCIDependencyProxyController) ProxyOCIReferrers(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	registry, fqImageName, upstreamImagePath := imageParamsFromContext(c)
	digest := c.Param("digest")
	upstreamPath := fmt.Sprintf("/v2/%s/referrers/%s", upstreamImagePath, digest)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.oci",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "oci"),
			attribute.String("proxy.type", "referrers"),
			attribute.String("proxy.registry", registry),
			attribute.String("proxy.image", fqImageName),
			attribute.String("proxy.digest", digest),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy request", "proxy", "oci", "type", "referrers", "image", fqImageName, "digest", digest)

	if notAllowed, reason := d.CheckNotAllowedPackage(ctx, ociEco, fqImageName, configs); notAllowed {
		return d.blockNotAllowedPackage(c, ociEco, fqImageName, reason)
	}
	if blocked, reason := d.checkMaliciousPackage(ctx, ociEco, fqImageName); blocked {
		return d.blockMaliciousPackage(c, ociEco, fqImageName, reason)
	}

	upstreamBase := upstreamURLForRegistry(registry)
	data, headers, statusCode, err := d.fetchOCIFromUpstream(ctx, c.Request().Method, upstreamBase, upstreamPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching OCI referrers from upstream", "proxy", "oci", "error", err, "image", fqImageName)
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch from upstream registry")
	}
	return d.passthroughUpstreamResponse(c, headers, statusCode, data)
}

// ProxyOCITagsList handles image tag listing.
// Routes:
//   - GET /oci/v2/:registry/:image/tags/list
//   - GET /oci/v2/:registry/:namespace/:image/tags/list
func (d *OCIDependencyProxyController) ProxyOCITagsList(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	registry, fqImageName, upstreamImagePath := imageParamsFromContext(c)
	upstreamPath := fmt.Sprintf("/v2/%s/tags/list", upstreamImagePath)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.oci",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "oci"),
			attribute.String("proxy.type", "tags-list"),
			attribute.String("proxy.registry", registry),
			attribute.String("proxy.image", fqImageName),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	slog.Info("Proxy request", "proxy", "oci", "type", "tags/list", "image", fqImageName)

	if notAllowed, reason := d.CheckNotAllowedPackage(ctx, ociEco, fqImageName, configs); notAllowed {
		return d.blockNotAllowedPackage(c, ociEco, fqImageName, reason)
	}
	if blocked, reason := d.checkMaliciousPackage(ctx, ociEco, fqImageName); blocked {
		return d.blockMaliciousPackage(c, ociEco, fqImageName, reason)
	}

	upstreamBase := upstreamURLForRegistry(registry)
	data, headers, statusCode, err := d.fetchOCIFromUpstream(ctx, c.Request().Method, upstreamBase, upstreamPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching OCI tags list from upstream", "proxy", "oci", "error", err, "image", fqImageName)
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch from upstream registry")
	}
	return d.passthroughUpstreamResponse(c, headers, statusCode, data)
}
