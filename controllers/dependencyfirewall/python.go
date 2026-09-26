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
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	pypiRegistry = "https://pypi.org"
	pypiFilesURL = "https://files.pythonhosted.org"
)

var (
	pypiProxyPrefixRe   = regexp.MustCompile(`^/api/v1/dependency-proxy/(?:[^/]+/)?pypi(?:/|$)`)
	pypiFilenameRe      = regexp.MustCompile(`^(.+?)-(\d[^-]*?)(?:-.+\.whl|\.zip|\.tar(?:\.gz|\.bz2|\.xz|\.lz|\.lzma)?|\.t[bgx]z|\.tlz)$`)
	pypiNameSeparatorRe = regexp.MustCompile(`[-_.]+`)
	pypiAbsoluteURLRe   = regexp.MustCompile(`(?:https?:)?//[^/"'\s]+/`)
)

// PythonDependencyProxyController handles PyPI dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type PythonDependencyProxyController struct {
	*DependencyProxyController
}

func NewPythonDependencyProxyController(controller *DependencyProxyController) *PythonDependencyProxyController {
	return &PythonDependencyProxyController{DependencyProxyController: controller}
}

type pypiEcosystem struct{}

var pypi pypiEcosystem

func (pypiEcosystem) name() string { return "pypi" }

func (pypiEcosystem) trimPrefix(path string) string {
	return trimWithRegex(path, pypiProxyPrefixRe)
}

func (pypiEcosystem) parsePackage(path string) (string, string) {
	path = strings.TrimPrefix(path, "/")
	if after, ok := strings.CutPrefix(path, "simple/"); ok {
		return strings.TrimSuffix(after, "/"), ""
	} else if strings.HasPrefix(path, "packages/") {

		filename := strings.TrimSuffix(filepath.Base(path), ".metadata")
		matches := pypiFilenameRe.FindStringSubmatch(filename)
		if len(matches) > 2 {
			return normalizePyPIName(matches[1]), matches[2]
		}
	}
	return "", ""
}

func normalizePyPIName(name string) string {
	return strings.ToLower(pypiNameSeparatorRe.ReplaceAllString(name, "-"))
}

func (pypiEcosystem) packageIdentifier(packageName, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:pypi/%s@%s", packageName, version)
	}
	return fmt.Sprintf("pkg:pypi/%s", packageName)
}

func (pypiEcosystem) writeResponse(c shared.Context, data []byte, path string, cached bool) error {
	if c.Response().Header().Get("Content-Type") == "" {
		contentType := "application/octet-stream"
		if strings.HasSuffix(path, ".whl") {
			contentType = "application/zip"
		} else if strings.Contains(path, "/simple/") {
			contentType = "text/html"
		}
		c.Response().Header().Set("Content-Type", contentType)
	}

	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("X-Proxy-Type", "pypi")
	return c.Blob(http.StatusOK, c.Response().Header().Get("Content-Type"), data)
}

// ProxyPyPIPackage handles explicit-version PyPI package downloads (from /packages/).
// Route: GET /pypi/packages/*
// @Summary Proxy PyPI package download
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Success 200 {file} binary
// @Router /dependency-proxy/pypi/packages/{path} [get]
// @Router /dependency-proxy/{secret}/pypi/packages/{path} [get]
func (d *PythonDependencyProxyController) ProxyPyPIPackage(c shared.Context) error {
	configs, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	requestPath := pypi.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.pypi",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "pypi"),
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

	slog.Info("Proxy request", "proxy", "pypi", "type", "package", "method", c.Request().Method, "path", requestPath)

	cacheKey := "pypi/" + requestPath
	if err := d.cache.ValidateKey(cacheKey); err != nil {
		slog.Warn("Invalid cache path", "proxy", "pypi", "path", requestPath, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid package path")
	}

	notAllowed, notAllowedReason := d.CheckNotAllowedPackage(ctx, pypi, requestPath, configs)
	if notAllowed {
		slog.Warn("Blocked not allowed package", "proxy", "pypi", "path", requestPath, "reason", notAllowedReason)
		return d.blockNotAllowedPackage(c, pypi, requestPath, notAllowedReason)
	}

	// Check for malicious packages BEFORE checking cache to prevent cache poisoning.
	packageName, version := pypi.parsePackage(requestPath)
	status, reason, err := d.checkMalicious(ctx, pypi, packageName, version)
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "pypi", "path", requestPath, "reason", reason)
		d.cache.Remove(cacheKey)
		return d.blockMaliciousPackage(c, pypi, requestPath, reason, http.StatusForbidden)
	}

	if entry, ok := d.cache.Get(cacheKey); ok {
		slog.Debug("Cache hit", "proxy", "pypi", "path", requestPath)
		if configs.MinReleaseAge > 0 {
			if time.Since(entry.releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
				return d.blockTooNewPackage(c, pypi, requestPath, entry.releaseTime, configs.MinReleaseAge)
			}
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return pypi.writeResponse(c, entry.data, requestPath, true)
		} else {
			span.SetAttributes(attribute.Bool("proxy.cache_hit", true))
			return pypi.writeResponse(c, entry.data, requestPath, true)
		}
	}

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	// Always resolve the release time, even without MinReleaseAge: the cache is shared
	// across proxy secrets, so an entry stored for one config must be checkable under
	// another. Files are only cached together with a known release time.
	releaseTime, releaseTimeErr := time.Time{}, fmt.Errorf("could not determine package and version from path")
	if packageName != "" {
		releaseTime, releaseTimeErr = d.fetchPyPIReleaseTime(ctx, packageName, version)
	}
	if releaseTimeErr != nil {
		slog.Warn("Could not determine release time", "proxy", "pypi", "package", packageName, "version", version, "error", releaseTimeErr)
		if configs.MinReleaseAge > 0 {
			// Fail closed: without a publish date the MinReleaseAge policy cannot be verified.
			return d.blockNotAllowedPackage(c, pypi, requestPath, fmt.Sprintf("Release time of package %s@%s could not be determined", packageName, version))
		}
	} else if configs.MinReleaseAge > 0 && time.Since(releaseTime) < time.Duration(configs.MinReleaseAge)*time.Hour {
		return d.blockTooNewPackage(c, pypi, requestPath, releaseTime, configs.MinReleaseAge)
	}

	data, headers, statusCode, err := d.fetchFromUpstream(ctx, pypi, pypiFilesURL, requestPath, c.Request().Header, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "pypi", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if releaseTimeErr == nil {
		if err := d.cache.Set(cacheKey, cacheValue{data: data, releaseTime: releaseTime}); err != nil {
			slog.Warn("Failed to cache response", "proxy", "pypi", "error", err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	return pypi.writeResponse(c, data, requestPath, false)
}

type pySimpleFile struct {
	CoreMetadata         any    `json:"core-metadata"`
	DataDistInfoMetadata any    `json:"data-dist-info-metadata"`
	Filename             string `json:"filename"`
	Hashes               struct {
		Sha256 string `json:"sha256"`
	} `json:"hashes"`
	Provenance     any       `json:"provenance"`
	RequiresPython any       `json:"requires-python"`
	Size           int       `json:"size"`
	UploadTime     time.Time `json:"upload-time"`
	URL            string    `json:"url"`
	Yanked         any       `json:"yanked"`
}

type pySimple struct {
	Files []pySimpleFile `json:"files"`
	Meta  struct {
		LastSerial int    `json:"_last-serial"`
		APIVersion string `json:"api-version"`
	} `json:"meta"`
	Name          string `json:"name"`
	ProjectStatus struct {
		Status string `json:"status"`
	} `json:"project-status"`
	Versions []string `json:"versions"`
}

// ProxyPyPISimple handles PyPI /simple/ metadata requests.
// Route: GET /pypi/simple/:package
// @Summary Proxy PyPI simple index metadata
// @Tags Dependency Firewall
// @Security PATAuth
// @Security BearerAuth
// @Param secret path string false "dependency proxy secret"
// @Param package path string true "PyPI package name"
// @Success 200 {string} string "HTML simple index"
// @Router /dependency-proxy/pypi/simple/{package} [get]
// @Router /dependency-proxy/{secret}/pypi/simple/{package} [get]
func (d *PythonDependencyProxyController) ProxyPyPISimple(c shared.Context) error {
	config, err := d.GetDependencyProxyConfigs(c)
	if err != nil {
		slog.Error("Error getting dependency proxy configs", "error", err)
		if strings.Contains(err.Error(), "invalid dependency proxy secret") {
			return echo.NewHTTPError(http.StatusUnauthorized, "dependency proxy secret is required or invalid")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load dependency proxy configuration")
	}

	pkgName := c.Param("package")
	requestPath := pypi.trimPrefix(c.Request().URL.Path)

	ctx, span := depProxyTracer.Start(c.Request().Context(), "dependency-proxy.pypi",
		trace.WithAttributes(
			attribute.String("proxy.ecosystem", "pypi"),
			attribute.String("proxy.type", "simple"),
			attribute.String("proxy.path", requestPath),
			attribute.String("http.method", c.Request().Method),
		),
	)
	defer span.End()
	c.SetRequest(c.Request().WithContext(ctx))

	if err := ensureReadMethod(c); err != nil {
		return err
	}

	slog.Info("Proxy request", "proxy", "pypi", "type", "simple", "method", c.Request().Method, "path", requestPath)

	span.SetAttributes(attribute.Bool("proxy.cache_hit", false))

	status, reason, err := d.checkMalicious(ctx, pypi, pkgName, "")
	if err != nil {
		slog.Error("Error checking malicious package", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check if package is malicious").WithInternal(err)
	}
	if status != 0 {
		slog.Warn("Blocked malicious package", "proxy", "pypi", "path", requestPath, "reason", reason)
		return d.blockMaliciousPackage(c, pypi, requestPath, reason, http.StatusForbidden)
	}
	headers := c.Request().Header
	headers.Set("Accept", "application/vnd.pypi.simple.v1+json")

	data, headers, statusCode, err := d.fetchPyPIFromUpstream(ctx, requestPath, headers)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		slog.Error("Error fetching from upstream", "proxy", "pypi", "error", err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to fetch from upstream")
	}

	if statusCode != http.StatusOK {
		slog.Debug("Upstream returned non-OK status", "proxy", "pypi", "status", statusCode)
		return d.passthroughUpstreamResponse(c, headers, statusCode, data)
	}

	if config.MinReleaseAge > 0 || len(config.Rules) > 0 {

		minAge := time.Duration(config.MinReleaseAge) * time.Hour
		data, err = filterPyPiSimpleIndex(data, func(version string, published time.Time) bool {
			if config.MinReleaseAge > 0 && (published.IsZero() || time.Since(published) < minAge) {
				return false
			}
			blocked, _ := matchRules(pypi.packageIdentifier(pkgName, version), config.Rules)
			return !blocked
		})
		if err != nil {
			slog.Error("Error filtering PyPI simple index", "proxy", "pypi", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to filter PyPI simple index").WithInternal(err)
		}
	}

	if contentType := headers.Get("Content-Type"); contentType != "" {
		c.Response().Header().Set("Content-Type", contentType)
	}

	data = pypiAbsoluteURLRe.ReplaceAllLiteral(data, []byte(pypiProxyPrefixRe.FindString(c.Request().URL.Path)))

	return pypi.writeResponse(c, data, requestPath, false)
}

func filterPyPiSimpleIndex(data []byte, keep func(version string, published time.Time) bool) ([]byte, error) {
	var simpleIndex pySimple
	if err := json.Unmarshal(data, &simpleIndex); err != nil {
		slog.Error("Error unmarshalling PyPI simple index", "proxy", "pypi", "error", err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to parse PyPI simple index").WithInternal(err)
	}

	filteredFiles := make([]pySimpleFile, 0, len(simpleIndex.Files))
	keptVersions := make(map[string]bool)
	for _, file := range simpleIndex.Files {
		_, version := pypi.parsePackage("packages/" + file.Filename)
		if version == "" {
			slog.Debug("Could not parse version from filename, skipping", "proxy", "pypi", "file", file.Filename)
			continue
		}
		if keep(version, file.UploadTime) {
			filteredFiles = append(filteredFiles, file)
			keptVersions[version] = true
		}
	}
	filteredVersions := make([]string, 0, len(simpleIndex.Versions))
	for _, version := range simpleIndex.Versions {
		if keptVersions[version] {
			filteredVersions = append(filteredVersions, version)
		}
	}

	simpleIndex.Files = filteredFiles
	simpleIndex.Versions = filteredVersions
	filteredData, err := json.Marshal(simpleIndex)

	if err != nil {
		slog.Error("Error marshalling filtered PyPI simple index", "proxy", "pypi", "error", err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "failed to serialize filtered PyPI simple index").WithInternal(err)
	}

	return filteredData, nil
}

func (d *PythonDependencyProxyController) fetchPyPIFromUpstream(ctx context.Context, requestPath string, headers http.Header) ([]byte, http.Header, int, error) {
	requestPath = strings.TrimRight(requestPath, "/")
	url, err := url.JoinPath(pypiRegistry, requestPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to join URL: %w", err)
	}
	slog.Debug("Fetching from upstream", "proxy", "pypi", "url", url)

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

// ExtractPyPIReleaseTime parses a PyPI JSON API response and returns the resolved version and its upload time.
// If version is empty, it uses info.version (the current release).
func (d *PythonDependencyProxyController) ExtractPyPIReleaseTime(data []byte, version string) (time.Time, error) {
	var metadata struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return time.Time{}, err
	}
	if version == "" {
		version = metadata.Info.Version
	}
	files, ok := metadata.Releases[version]
	if !ok || len(files) == 0 {
		return time.Time{}, fmt.Errorf("version %s not found in PyPI metadata", version)
	}
	// A version's release time is its earliest upload - wheels are often uploaded later
	// than the sdist. The simple index filter uses the same definition per file.
	var earliest time.Time
	for _, file := range files {
		t, err := time.Parse(time.RFC3339Nano, file.UploadTime)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse upload time for version %s: %w", version, err)
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest, nil
}

// fetchPyPIReleaseTime fetches the PyPI JSON API and returns the resolved version and its release time.
func (d *PythonDependencyProxyController) fetchPyPIReleaseTime(ctx context.Context, pkgName, version string) (time.Time, error) {
	data, _, statusCode, err := d.fetchPyPIFromUpstream(ctx, "/pypi/"+pkgName+"/json", http.Header{})
	if err != nil {
		return time.Time{}, err
	}
	if statusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("upstream returned status %d for release metadata", statusCode)
	}
	return d.ExtractPyPIReleaseTime(data, version)
}
