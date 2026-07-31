package services

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFetchSbomsFromUpstream_PassesURLNotRef(t *testing.T) {
	t.Run("should pass URL parameter to SBOMGraphFromCycloneDX instead of ref", func(t *testing.T) {
		// Create a mock HTTP server that returns a valid SBOM
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sbom.json" {
				// Return a valid minimal CycloneDX SBOM
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{
					"bomFormat": "CycloneDX",
					"specVersion": "1.4",
					"metadata": {
						"component": {
							"bom-ref": "pkg:npm/test-component@1.0.0",
							"name": "test-component",
							"version": "1.0.0"
						}
					},
					"version": 1,
					"components": []
				}`))
				if err != nil {
					t.Fatalf("failed to write response: %v", err)
				}
			}
		}))
		defer server.Close()

		sbomURL := server.URL + "/sbom.json"
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLs := FetchSbomsFromUpstream(context.Background(), artifactName, ref, []string{sbomURL})

		// Verify the SBOM was processed successfully with the correct URL
		assert.Equal(t, 1, len(boms), "should have fetched 1 SBOM")
		assert.Equal(t, 1, len(validURLs), "should have 1 valid URL")
		assert.Equal(t, 0, len(invalidURLs), "should have 0 invalid URLs")

		// Verify the URL was added to validURLs list (not the ref)
		assert.Contains(t, validURLs, sbomURL)
		// Ref should not appear anywhere since URL is passed instead
		assert.NotContains(t, validURLs, ref)
	})

	t.Run("should reject invalid URLs", func(t *testing.T) {

		invalidURLs := []string{
			"",
			"not-a-url",
			"ftp://invalid-protocol.com/sbom.json",
		}
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLsList := FetchSbomsFromUpstream(context.Background(), artifactName, ref, invalidURLs)

		assert.Equal(t, 0, len(boms))
		assert.Equal(t, 0, len(validURLs))
		assert.Equal(t, 3, len(invalidURLsList))
	})

	t.Run("should handle HTTP errors gracefully", func(t *testing.T) {
		// Create a mock HTTP server that returns a 500 error
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		sbomURL := server.URL + "/sbom.json"
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLs := FetchSbomsFromUpstream(context.Background(), artifactName, ref, []string{sbomURL})

		// HTTP errors should result in invalid URLs
		assert.Equal(t, 0, len(boms))
		assert.Equal(t, 0, len(validURLs))
		assert.Equal(t, 1, len(invalidURLs))
		assert.Equal(t, sbomURL, invalidURLs[0].URL)
	})
}

func TestFetchVexFromGitHub(t *testing.T) {
	newZipHandler := func(t *testing.T, wantPath string, files map[string]string) http.HandlerFunc {
		t.Helper()

		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		paths := make([]string, 0, len(files))
		for filePath := range files {
			paths = append(paths, filePath)
		}
		sort.Strings(paths)
		for _, filePath := range paths {
			content := files[filePath]
			entry, err := zw.Create(filePath)
			if err != nil {
				t.Fatalf("failed to create zip entry %s: %v", filePath, err)
			}
			if _, err := entry.Write([]byte(content)); err != nil {
				t.Fatalf("failed to write zip entry %s: %v", filePath, err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("failed to close zip writer: %v", err)
		}
		zipBytes := buf.Bytes()

		return func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, wantPath, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zipBytes)
		}
	}

	fetcherWithServer := func(server *httptest.Server) gitHubVexFetcher {
		return gitHubVexFetcher{baseURL: server.URL}
	}

	t.Run("should fetch openvex reports from json files in the repository", func(t *testing.T) {
		calls := 0
		handler := newZipHandler(t, "/octo-org/openvex-repo/archive/refs/heads/main.zip", map[string]string{
			"reports/openvex.json": mustMarshalJSON(t, map[string]any{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "openvex-1",
				"author":    "test-author",
				"timestamp": time.Date(2026, time.May, 20, 12, 0, 0, 0, time.UTC),
				"version":   1,
				"statements": []any{
					map[string]any{
						"vulnerability": map[string]any{"name": "CVE-2024-1234"},
						"products": []any{
							map[string]any{"@id": "pkg:npm/test-component@1.0.0"},
						},
						"status": "not_affected",
					},
				},
			}),
			"README.md": "# ignore me",
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			handler(w, r)
		}))
		defer server.Close()

		reports, err := fetcherWithServer(server).FetchVexFromGitHub(context.Background(), "https://github.com/octo-org/openvex-repo", "")
		assert.NoError(t, err)
		assert.Len(t, reports, 1)
		// the source of a rule fetched from a GitHub repo is the path of the file it was parsed from
		assert.Equal(t, "reports/openvex.json", reports[0].VexSource)
		assert.Contains(t, reports[0].CELExpression, "CVE-2024-1234")
		assert.Equal(t, 1, calls)
	})

	t.Run("should fetch multiple openvex reports from multiple json files", func(t *testing.T) {
		calls := 0
		handler := newZipHandler(t, "/octo-org/multi-vex-repo/archive/refs/heads/develop.zip", map[string]string{
			"vex/vex1.json": mustMarshalJSON(t, map[string]any{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "openvex-first",
				"author":    "author-one",
				"timestamp": time.Date(2026, time.May, 20, 12, 0, 0, 0, time.UTC),
				"version":   1,
				"statements": []any{
					map[string]any{
						"vulnerability": map[string]any{"name": "CVE-2024-0001"},
						"products": []any{
							map[string]any{"@id": "pkg:npm/comp-one@1.0.0"},
						},
						"status": "not_affected",
					},
				},
			}),
			"vex/vex2.json": mustMarshalJSON(t, map[string]any{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "openvex-second",
				"author":    "author-two",
				"timestamp": time.Date(2026, time.May, 20, 12, 0, 0, 0, time.UTC),
				"version":   1,
				"statements": []any{
					map[string]any{
						"vulnerability": map[string]any{"name": "CVE-2024-0002"},
						"products": []any{
							map[string]any{"@id": "pkg:npm/comp-two@1.0.0"},
						},
						"status": "not_affected",
					},
				},
			}),
			"README.md": "# ignore me",
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			handler(w, r)
		}))
		defer server.Close()

		reports, err := fetcherWithServer(server).FetchVexFromGitHub(context.Background(), "https://github.com/octo-org/multi-vex-repo", "develop")
		assert.NoError(t, err)
		assert.Len(t, reports, 2)
		// the source of each rule is the path of the file it was parsed from, one rule per file here
		sources := []string{reports[0].VexSource, reports[1].VexSource}
		assert.ElementsMatch(t, []string{"vex/vex1.json", "vex/vex2.json"}, sources)
		cels := []string{reports[0].CELExpression, reports[1].CELExpression}
		assert.Contains(t, cels[0]+cels[1], "CVE-2024-0001")
		assert.Contains(t, cels[0]+cels[1], "CVE-2024-0002")
		assert.Equal(t, 1, calls)
	})

	t.Run("should handle HTTP errors from GitHub", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		reports, err := fetcherWithServer(server).FetchVexFromGitHub(context.Background(), "https://github.com/octo-org/missing-repo", "")
		assert.Error(t, err)
		assert.Nil(t, reports)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("should reject non github urls", func(t *testing.T) {
		reports, err := NewGitHubVexFetcher().FetchVexFromGitHub(context.Background(), "https://example.com/repo", "")
		assert.Error(t, err)
		assert.Nil(t, reports)
		assert.Contains(t, err.Error(), "invalid github repository url")
	})
}
