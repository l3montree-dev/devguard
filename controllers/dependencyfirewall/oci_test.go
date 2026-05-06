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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// ── ociEcosystem ────────────────────────────────────────────────────────────

func TestOCIEcosystemParsePackage(t *testing.T) {
	cases := []struct {
		name            string
		path            string
		expectedPkg     string
		expectedVersion string
	}{
		{
			name:            "manifest by tag",
			path:            "/v2/docker.io/library/nginx/manifests/latest",
			expectedPkg:     "docker.io/library/nginx",
			expectedVersion: "latest",
		},
		{
			name:            "manifest by digest",
			path:            "/v2/docker.io/library/nginx/manifests/sha256:abc123",
			expectedPkg:     "docker.io/library/nginx",
			expectedVersion: "sha256:abc123",
		},
		{
			name:            "1-segment image manifest",
			path:            "/v2/docker.io/nginx/manifests/latest",
			expectedPkg:     "docker.io/nginx",
			expectedVersion: "latest",
		},
		{
			name:            "blob path",
			path:            "/v2/docker.io/library/nginx/blobs/sha256:deadbeef",
			expectedPkg:     "docker.io/library/nginx",
			expectedVersion: "sha256:deadbeef",
		},
		{
			name:            "tags/list path",
			path:            "/v2/docker.io/library/nginx/tags/list",
			expectedPkg:     "docker.io/library/nginx",
			expectedVersion: "",
		},
		{
			name:            "path without leading slash",
			path:            "v2/ghcr.io/org/repo/manifests/v1.0",
			expectedPkg:     "ghcr.io/org/repo",
			expectedVersion: "v1.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, version := ociEco.parsePackage(tc.path)
			if pkg != tc.expectedPkg || version != tc.expectedVersion {
				t.Fatalf("expected (%q, %q), got (%q, %q)", tc.expectedPkg, tc.expectedVersion, pkg, version)
			}
		})
	}
}

func TestOCIEcosystemIsCached(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file is not cached", func(t *testing.T) {
		if ociEco.isCached(filepath.Join(dir, "nonexistent")) {
			t.Fatal("expected false for missing file")
		}
	})

	t.Run("blob is always cached once present", func(t *testing.T) {
		p := filepath.Join(dir, "blobs", "sha256_abc")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-48 * time.Hour)
		_ = os.Chtimes(p, old, old)
		if !ociEco.isCached(p) {
			t.Fatal("expected blob to be cached regardless of age")
		}
	})

	t.Run("digest-pinned manifest is always cached", func(t *testing.T) {
		p := filepath.Join(dir, "manifests", "sha256_deadbeef")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("manifest"), 0644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-48 * time.Hour)
		_ = os.Chtimes(p, old, old)
		if !ociEco.isCached(p) {
			t.Fatal("expected digest manifest to be cached regardless of age")
		}
	})

	t.Run("tag manifest within TTL is cached", func(t *testing.T) {
		p := filepath.Join(dir, "manifests", "latest")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("manifest"), 0644); err != nil {
			t.Fatal(err)
		}
		if !ociEco.isCached(p) {
			t.Fatal("expected fresh tag manifest to be cached")
		}
	})

	t.Run("tag manifest past TTL is not cached", func(t *testing.T) {
		p := filepath.Join(dir, "manifests", "old-tag")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("manifest"), 0644); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * time.Hour)
		_ = os.Chtimes(p, old, old)
		if ociEco.isCached(p) {
			t.Fatal("expected stale tag manifest to not be cached")
		}
	})
}

// ── ociSafeCachePath ─────────────────────────────────────────────────────────

func TestOCISafeCachePath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"sha256:abc123", "sha256_abc123"},
		{"/v2/docker.io/library/nginx/manifests/sha256:dead", "/v2/docker.io/library/nginx/manifests/sha256_dead"},
		{"/v2/docker.io/library/nginx/blobs/sha256:beef", "/v2/docker.io/library/nginx/blobs/sha256_beef"},
		{"no-colons-here", "no-colons-here"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := ociSafeCachePath(tc.input); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// ── isAllowedRegistry ────────────────────────────────────────────────────────

func TestIsAllowedRegistry(t *testing.T) {
	cases := map[string]bool{
		"docker.io":         true,
		"ghcr.io":           true,
		"quay.io":           true,
		"gcr.io":            true,
		"registry.k8s.io":   true,
		"public.ecr.aws":    true,
		"mcr.microsoft.com": true,
		"evil.com":          false,
		"unknown.io":        false,
		"1.2.3.4":           false, // IPv4 literal
		"::1":               false, // IPv6 literal
		"docker.io:443":     false, // host:port form
		"":                  false,
	}
	for input, want := range cases {
		if got := isAllowedRegistry(input); got != want {
			t.Errorf("isAllowedRegistry(%q) = %v, want %v", input, got, want)
		}
	}
}

// TestSupportedOCIRegistriesDerivations ensures the lookup tables stay in
// sync with the supportedOCIRegistries source list. If someone adds an entry
// to the list but a derived map isn't rebuilt (e.g. init() bug), this fails.
func TestSupportedOCIRegistriesDerivations(t *testing.T) {
	if len(allowedOCIRegistries) != len(supportedOCIRegistries) {
		t.Fatalf("allowedOCIRegistries size mismatch: got %d, want %d",
			len(allowedOCIRegistries), len(supportedOCIRegistries))
	}
	for _, r := range supportedOCIRegistries {
		if _, ok := registryUpstreamHosts[r.pathName]; !ok {
			t.Errorf("registryUpstreamHosts missing entry for %q", r.pathName)
		}
		if _, ok := registryAuthHosts[r.upstreamHost]; !ok {
			t.Errorf("registryAuthHosts missing entry for %q", r.upstreamHost)
		}
	}
}

// ── upstreamURLForRegistry ────────────────────────────────────────────────────

func TestUpstreamURLForRegistry(t *testing.T) {
	cases := []struct {
		registry string
		expected string
	}{
		{"docker.io", "https://registry-1.docker.io"},
		{"ghcr.io", "https://ghcr.io"},
		{"registry.example.com", "https://registry.example.com"},
		{"quay.io", "https://quay.io"},
	}

	for _, tc := range cases {
		t.Run(tc.registry, func(t *testing.T) {
			if got := upstreamURLForRegistry(tc.registry); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// ── parseBearerChallenge ─────────────────────────────────────────────────────

func TestParseBearerChallenge(t *testing.T) {
	realm, service, scope := parseBearerChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`)

	if realm != "https://auth.docker.io/token" {
		t.Fatalf("realm: expected %q, got %q", "https://auth.docker.io/token", realm)
	}
	if service != "registry.docker.io" {
		t.Fatalf("service: expected %q, got %q", "registry.docker.io", service)
	}
	if scope != "repository:library/nginx:pull" {
		t.Fatalf("scope: expected %q, got %q", "repository:library/nginx:pull", scope)
	}

	t.Run("missing realm returns empty string", func(t *testing.T) {
		realm, service, scope := parseBearerChallenge(`Bearer service="foo",scope="bar"`)
		if realm != "" || service != "foo" || scope != "bar" {
			t.Fatalf("unexpected values: realm=%q service=%q scope=%q", realm, service, scope)
		}
	})

	t.Run("empty header returns all empty", func(t *testing.T) {
		realm, service, scope := parseBearerChallenge("")
		if realm != "" || service != "" || scope != "" {
			t.Fatal("expected all empty for empty header")
		}
	})
}

// ── imageParamsFromContext ────────────────────────────────────────────────────

func newTestEchoContext(params map[string]string) echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	names := make([]string, 0, len(params))
	values := make([]string, 0, len(params))
	for k, v := range params {
		names = append(names, k)
		values = append(values, v)
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	return c
}

func TestImageParamsFromContext(t *testing.T) {
	cases := []struct {
		name                 string
		params               map[string]string
		expectedRegistry     string
		expectedFQImageName  string
		expectedUpstreamPath string
	}{
		{
			name: "1-segment image",
			params: map[string]string{
				"registry": "docker.io",
				"image":    "nginx",
			},
			expectedRegistry:     "docker.io",
			expectedFQImageName:  "docker.io/nginx",
			expectedUpstreamPath: "nginx",
		},
		{
			name: "2-segment image with namespace",
			params: map[string]string{
				"registry":  "docker.io",
				"namespace": "library",
				"image":     "nginx",
			},
			expectedRegistry:     "docker.io",
			expectedFQImageName:  "docker.io/library/nginx",
			expectedUpstreamPath: "library/nginx",
		},
		{
			name: "3-segment image with ns1 and ns2",
			params: map[string]string{
				"registry": "ghcr.io",
				"ns1":      "org",
				"ns2":      "team",
				"image":    "repo",
			},
			expectedRegistry:     "ghcr.io",
			expectedFQImageName:  "ghcr.io/org/team/repo",
			expectedUpstreamPath: "org/team/repo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestEchoContext(tc.params)
			registry, fqImageName, upstreamPath := imageParamsFromContext(c)

			if registry != tc.expectedRegistry {
				t.Errorf("registry: expected %q, got %q", tc.expectedRegistry, registry)
			}
			if fqImageName != tc.expectedFQImageName {
				t.Errorf("fqImageName: expected %q, got %q", tc.expectedFQImageName, fqImageName)
			}
			if upstreamPath != tc.expectedUpstreamPath {
				t.Errorf("upstreamPath: expected %q, got %q", tc.expectedUpstreamPath, upstreamPath)
			}
		})
	}
}

// ── ociEcosystem.packageIdentifier ───────────────────────────────────────────

func TestOCIEcosystemPackageIdentifier(t *testing.T) {
	cases := []struct {
		name     string
		pkg      string
		version  string
		expected string
	}{
		{"tag", "docker.io/library/nginx", "latest", "docker.io/library/nginx:latest"},
		{"digest", "docker.io/library/nginx", "sha256:abc123", "docker.io/library/nginx@sha256:abc123"},
		{"no version", "docker.io/library/nginx", "", "docker.io/library/nginx"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ociEco.packageIdentifier(tc.pkg, tc.version); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

// ── CheckNotAllowedPackage for OCI rules ─────────────────────────────────────

func TestCheckNotAllowedPackageOCI(t *testing.T) {
	d := &DependencyProxyController{}

	cases := []struct {
		name            string
		path            string
		rules           []string
		expectedBlocked bool
		expectedReason  string
	}{
		{
			name:            "blocks exact image by plain reference",
			path:            "/v2/docker.io/library/nginx/manifests/latest",
			rules:           []string{"docker.io/library/nginx:latest"},
			expectedBlocked: true,
			expectedReason:  "docker.io/library/nginx:latest",
		},
		{
			name:            "blocks image by wildcard tag",
			path:            "/v2/docker.io/library/nginx/manifests/1.27.0",
			rules:           []string{"docker.io/library/nginx:*"},
			expectedBlocked: true,
			expectedReason:  "docker.io/library/nginx:*",
		},
		{
			name:            "allows image not matching rule",
			path:            "/v2/docker.io/library/alpine/manifests/latest",
			rules:           []string{"docker.io/library/nginx:*"},
			expectedBlocked: false,
		},
		{
			name:            "wildcard blocks all images",
			path:            "/v2/ghcr.io/org/repo/manifests/v1.0",
			rules:           []string{"*"},
			expectedBlocked: true,
		},
		{
			name:            "negate rule overrides wildcard for specific image",
			path:            "/v2/docker.io/library/alpine/manifests/latest",
			rules:           []string{"*", "!docker.io/library/alpine:latest"},
			expectedBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := d.CheckNotAllowedPackage(
				newTestEchoContext(nil).Request().Context(),
				ociEco,
				tc.path,
				DependencyProxyConfigs{Rules: tc.rules},
			)

			if blocked != tc.expectedBlocked {
				t.Fatalf("expected blocked=%v, got blocked=%v (reason=%q)", tc.expectedBlocked, blocked, reason)
			}
			if tc.expectedReason != "" && !strings.Contains(reason, tc.expectedReason) {
				t.Fatalf("expected reason to contain %q, got %q", tc.expectedReason, reason)
			}
		})
	}
}

// ── ProxyOCIVersionCheck ─────────────────────────────────────────────────────

func TestProxyOCIVersionCheck(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	ctrl := &OCIDependencyProxyController{DependencyProxyController: &DependencyProxyController{}}
	if err := ctrl.ProxyOCIVersionCheck(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("expected valid JSON body: %v", err)
	}
}

// ── validateRealmHost ────────────────────────────────────────────────────────

func TestValidateRealmHost(t *testing.T) {
	cases := []struct {
		name         string
		realm        string
		upstreamHost string
		wantErr      string
	}{
		{
			name:         "same-host https realm passes",
			realm:        "https://example.com/token",
			upstreamHost: "example.com",
		},
		{
			name:         "allowlisted delegation passes",
			realm:        "https://auth.docker.io/token",
			upstreamHost: "registry-1.docker.io",
		},
		{
			name:         "non-https realm rejected",
			realm:        "http://example.com/token",
			upstreamHost: "example.com",
			wantErr:      "realm must use https",
		},
		{
			name:         "SSRF realm to metadata IP rejected",
			realm:        "http://169.254.169.254/latest/meta-data/",
			upstreamHost: "evil.com",
			wantErr:      "realm must use https",
		},
		{
			name:         "https foreign host rejected for known registry",
			realm:        "https://attacker.example/token",
			upstreamHost: "registry-1.docker.io",
			wantErr:      "not allowed",
		},
		{
			name:         "unknown registry has no allowed delegation hosts",
			realm:        "https://attacker.example/token",
			upstreamHost: "evil.com",
			wantErr:      "not allowed",
		},
		{
			name:         "malformed realm rejected",
			realm:        "://invalid",
			upstreamHost: "example.com",
			wantErr:      "realm is not a valid URL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRealmHost(tc.realm, tc.upstreamHost)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// ── fetchRegistryToken realm validation ──────────────────────────────────────

// TestFetchRegistryTokenRejectsSSRFRealm reproduces the PoC from issue #1921:
// a malicious registry advertises realm pointing at an internal address.
// The fix must reject this before any HTTP request is issued.
func TestFetchRegistryTokenRejectsSSRFRealm(t *testing.T) {
	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: http.DefaultClient},
	}

	poc := `Bearer realm="http://169.254.169.254/latest/meta-data/",service="evil"`
	token, err := ctrl.fetchRegistryToken(t.Context(), "evil.com", poc)
	if err == nil {
		t.Fatalf("expected SSRF realm to be rejected, got token=%q", token)
	}
	if token != "" {
		t.Fatalf("expected empty token on rejection, got %q", token)
	}
}

func TestFetchRegistryTokenRejectsForeignHost(t *testing.T) {
	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: http.DefaultClient},
	}

	// docker.io legitimately delegates to auth.docker.io; a foreign host must be refused.
	header := `Bearer realm="https://attacker.example/token",service="registry.docker.io"`
	_, err := ctrl.fetchRegistryToken(t.Context(), "registry-1.docker.io", header)
	if err == nil {
		t.Fatal("expected foreign host realm to be rejected")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got %v", err)
	}
}

func TestFetchRegistryTokenAcceptsAllowlistedDelegation(t *testing.T) {
	// When the realm points to an allowlisted delegation host, validation passes
	// and we attempt the token call (which then fails because we're not actually
	// talking to auth.docker.io). The test asserts the validator did not block;
	// any error must be from the network/transport layer, not realm validation.
	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: &http.Client{Transport: errTransport{}}},
	}

	header := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`
	_, err := ctrl.fetchRegistryToken(t.Context(), "registry-1.docker.io", header)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if strings.Contains(err.Error(), "not allowed") || strings.Contains(err.Error(), "must use https") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

// errTransport short-circuits any HTTP call so tests that want to verify the
// validator without hitting the network can do so deterministically.
type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrHandlerTimeout
}
