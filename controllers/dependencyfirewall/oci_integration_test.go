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

// Integration tests that exercise the OCI proxy against a real (in-process)
// HTTP/HTTPS server stood up via httptest. Pure unit tests live in oci_test.go.

package dependencyfirewall

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── fetchOCIFromUpstream — happy-path token auth ─────────────────────────────

func TestFetchOCIFromUpstreamTokenAuth(t *testing.T) {
	// TLS + same-host token endpoint: realm validation requires https and that
	// the realm host either equals the upstream host or is allowlisted.
	var server *httptest.Server
	callCount := 0
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(dockerTokenResponse{Token: "test-token"})
			return
		}
		callCount++
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate", `Bearer realm="`+server.URL+`/token",service="test-registry",scope="repository:library/nginx:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	}))
	defer server.Close()

	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: server.Client()},
	}

	data, headers, status, err := ctrl.fetchOCIFromUpstream(
		t.Context(),
		http.MethodGet,
		server.URL,
		"/v2/library/nginx/manifests/latest",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if !strings.Contains(string(data), "schemaVersion") {
		t.Fatalf("unexpected body: %s", data)
	}
	if headers.Get("Content-Type") == "" {
		t.Fatal("expected Content-Type header to be forwarded")
	}
	if callCount != 2 {
		t.Fatalf("expected 2 upstream calls (challenge + retry with token), got %d", callCount)
	}
}

// ── fetchOCIFromUpstream — HEAD passthrough ──────────────────────────────────

func TestFetchOCIFromUpstreamHEAD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "want HEAD", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: srv.Client()},
	}

	data, headers, status, err := ctrl.fetchOCIFromUpstream(t.Context(), http.MethodHead, srv.URL, "/v2/library/nginx/manifests/latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if data != nil {
		t.Fatal("expected nil body for HEAD response")
	}
	if headers.Get("Docker-Content-Digest") != "sha256:abc" {
		t.Fatalf("expected digest header, got %q", headers.Get("Docker-Content-Digest"))
	}
}

// ── End-to-end SSRF regression tests (issue #1921) ───────────────────────────

// TestFetchOCIFromUpstreamRejectsSSRFRealmEndToEnd is the live PoC regression
// for issue #1921. A real HTTPS upstream returns a 401 advertising a malicious
// realm pointing at the AWS metadata IP. DevGuard must refuse before issuing
// any token request — the server records every hit, and there must be exactly
// one (the initial manifest fetch that produced the 401).
func TestFetchOCIFromUpstreamRejectsSSRFRealmEndToEnd(t *testing.T) {
	var hits []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		w.Header().Set("Www-Authenticate", `Bearer realm="http://169.254.169.254/latest/meta-data/",service="evil"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: server.Client()},
	}

	_, _, _, err := ctrl.fetchOCIFromUpstream(
		t.Context(),
		http.MethodGet,
		server.URL,
		"/v2/library/nginx/manifests/latest",
	)
	if err == nil {
		t.Fatal("expected SSRF realm to be rejected, got no error")
	}
	if !strings.Contains(err.Error(), "realm must use https") {
		t.Fatalf("expected 'realm must use https' error, got %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly one upstream hit (the 401 challenge), got %d: %v", len(hits), hits)
	}
	if hits[0] != "/v2/library/nginx/manifests/latest" {
		t.Fatalf("unexpected upstream path: %q", hits[0])
	}
}

// TestFetchOCIFromUpstreamRejectsForeignRealmEndToEnd verifies that even when
// the malicious upstream serves over HTTPS, a realm pointing at a host outside
// the registry's allowlist is refused (and no token request is issued).
func TestFetchOCIFromUpstreamRejectsForeignRealmEndToEnd(t *testing.T) {
	var hits []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		w.Header().Set("Www-Authenticate", `Bearer realm="https://attacker.example/token",service="evil"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	ctrl := &OCIDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{client: server.Client()},
	}

	_, _, _, err := ctrl.fetchOCIFromUpstream(
		t.Context(),
		http.MethodGet,
		server.URL,
		"/v2/library/nginx/manifests/latest",
	)
	if err == nil {
		t.Fatal("expected foreign realm to be rejected")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly one upstream hit, got %d: %v", len(hits), hits)
	}
}
