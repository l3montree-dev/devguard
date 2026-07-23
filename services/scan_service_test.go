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
package services

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFirstPartyVulnHash(t *testing.T) {
	t.Run("should return the same hash for two equal vulnerabilities", func(t *testing.T) {
		snippet1 := dtos.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents1 := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{snippet1},
		}
		snippetJSON1, err := transformer.SnippetContentsToJSON(snippetContents1)
		assert.NoError(t, err)
		vuln1 := models.FirstPartyVuln{
			URI:             "test-uri",
			SnippetContents: snippetJSON1,
			Vulnerability: models.Vulnerability{
				Message: new("Test message"),
			},
		}

		snippet2 := dtos.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents2 := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{snippet2},
		}
		snippetJSON2, err := transformer.SnippetContentsToJSON(snippetContents2)
		assert.NoError(t, err)

		vuln2 := models.FirstPartyVuln{
			URI:             "test-uri",
			SnippetContents: snippetJSON2,
			Vulnerability: models.Vulnerability{
				Message: new("other message"),
			},
		}

		assert.Equal(t, vuln1.CalculateHash(), vuln2.CalculateHash())
	})

	t.Run("should return different hashes for different vulnerabilities", func(t *testing.T) {
		snippet1 := dtos.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents1 := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{snippet1},
		}
		snippetJSON1, err := transformer.SnippetContentsToJSON(snippetContents1)
		assert.NoError(t, err)
		vuln1 := models.FirstPartyVuln{
			URI:             "test-uri",
			SnippetContents: snippetJSON1,
			Vulnerability: models.Vulnerability{
				Message: new("Test message"),
			},
		}

		snippet2 := dtos.SnippetContent{
			StartLine:   3,
			EndLine:     4,
			StartColumn: 5,
			EndColumn:   6,
			Snippet:     "AnotherSnippet",
		}
		snippetContents2 := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{snippet2},
		}
		snippetJSON2, err := transformer.SnippetContentsToJSON(snippetContents2)
		assert.NoError(t, err)

		vuln2 := models.FirstPartyVuln{
			URI:             "another-uri",
			SnippetContents: snippetJSON2,
			Vulnerability: models.Vulnerability{
				Message: new("Another message"),
			},
		}

		assert.NotEqual(t, vuln1.CalculateHash(), vuln2.CalculateHash())
	})

	t.Run("should take the hash of the vulnerability, if it exists", func(t *testing.T) {
		vuln := sarif.SarifSchema210Json{
			Version: "2.1.0",
			Schema:  new("https://json.schemastore.org/sarif-2.1.0.json"),
			Runs: []sarif.Run{
				{
					Results: []sarif.Result{
						{
							RuleID: new("test-rule"),
							Locations: []sarif.Location{
								{
									PhysicalLocation: sarif.PhysicalLocation{
										ArtifactLocation: sarif.ArtifactLocation{
											URI: new("test-uri"),
										},
										Region: &sarif.Region{
											StartLine: new(1),
											Snippet: &sarif.ArtifactContent{

												Text: new("TestSnippet"),
											},
										},
									},
								},
							},
							Fingerprints: map[string]string{
								"calculatedFingerprint": "test-fingerprint",
							},
						},
					},
				},
			},
		}

		scanService := mocks.NewScanService(t)

		// create the expected FirstPartyVuln with the fingerprint
		// the ID should be set to the fingerprint when it exists
		expectedVuln := models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				ID: uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"), // this should match the fingerprint
			},
			Fingerprint: "test-fingerprint",
		}

		// set up the mock expectation
		scanService.On("HandleFirstPartyVulnResult",
			mock.Anything,
			models.Org{},
			models.Project{},
			models.Asset{},
			&models.AssetVersion{Name: "test-asset-version"},
			vuln,
			"scannerID",
			"userID",
			(*string)(nil)).Return([]models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{expectedVuln}, nil)

		_, _, r, err := scanService.HandleFirstPartyVulnResult(
			context.Background(),
			models.Org{},
			models.Project{},
			models.Asset{},
			&models.AssetVersion{
				Name: "test-asset-version",
			},
			vuln,
			"scannerID",
			"userID",
			nil)
		assert.NoError(t, err)
		assert.Len(t, r, 1)
		assert.Equal(t, "ffffffff-ffff-ffff-ffff-ffffffffffff", r[0].ID.String())
	})

}

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

		service := &scanService{
			sbomScanner: mocks.NewSBOMScanner(t),
		}

		sbomURL := server.URL + "/sbom.json"
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLs := service.FetchSbomsFromUpstream(context.Background(), artifactName, ref, []string{sbomURL})

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
		service := &scanService{
			sbomScanner: mocks.NewSBOMScanner(t),
		}

		invalidURLs := []string{
			"",
			"not-a-url",
			"ftp://invalid-protocol.com/sbom.json",
		}
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLsList := service.FetchSbomsFromUpstream(context.Background(), artifactName, ref, invalidURLs)

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

		service := &scanService{
			sbomScanner: mocks.NewSBOMScanner(t),
		}

		sbomURL := server.URL + "/sbom.json"
		artifactName := "test-artifact"
		ref := "main"

		boms, validURLs, invalidURLs := service.FetchSbomsFromUpstream(context.Background(), artifactName, ref, []string{sbomURL})

		// HTTP errors should result in invalid URLs
		assert.Equal(t, 0, len(boms))
		assert.Equal(t, 0, len(validURLs))
		assert.Equal(t, 1, len(invalidURLs))
		assert.Equal(t, sbomURL, invalidURLs[0].URL)
	})
}

func TestFetchOpenVexFromGitHub(t *testing.T) {
	originalDownloadRawFileFn := downloadRawFileFn
	t.Cleanup(func() {
		downloadRawFileFn = originalDownloadRawFileFn
	})

	newZipResponse := func(t *testing.T, files map[string]string) *http.Response {
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

		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
		}
	}

	t.Run("should fetch openvex reports from json files in the repository", func(t *testing.T) {
		calls := 0
		downloadRawFileFn = func(ctx context.Context, owner, repo, branch string) (*http.Response, error) {
			calls++
			assert.Equal(t, "octo-org", owner)
			assert.Equal(t, "openvex-repo", repo)
			assert.Equal(t, "main", branch)

			ts := time.Date(2026, time.May, 20, 12, 0, 0, 0, time.UTC)
			return newZipResponse(t, map[string]string{
				"reports/openvex.json": mustMarshalJSON(t, map[string]any{
					"@context":   "https://openvex.dev/ns/v0.2.0",
					"@id":        "openvex-1",
					"author":     "test-author",
					"timestamp":  ts,
					"version":    1,
					"statements": []any{},
				}),
				"README.md": "# ignore me",
			}), nil
		}

		service := &scanService{}
		reports, err := service.FetchOpenVexFromGitHub(context.Background(), "https://github.com/octo-org/openvex-repo", "")
		assert.NoError(t, err)
		assert.Len(t, reports, 1)
		assert.Equal(t, "https://github.com/octo-org/openvex-repo", reports[0].Source)
		assert.Equal(t, "openvex-1", reports[0].Report.ID)
		assert.Equal(t, "test-author", reports[0].Report.Author)
		assert.Equal(t, 1, reports[0].Report.Version)
		assert.Equal(t, 1, calls)
	})

	t.Run("should fetch multiple openvex reports from multiple json files", func(t *testing.T) {
		calls := 0
		downloadRawFileFn = func(ctx context.Context, owner, repo, branch string) (*http.Response, error) {
			calls++
			assert.Equal(t, "octo-org", owner)
			assert.Equal(t, "multi-vex-repo", repo)
			assert.Equal(t, "develop", branch)

			ts := time.Date(2026, time.May, 20, 12, 0, 0, 0, time.UTC)
			return newZipResponse(t, map[string]string{
				"vex/vex1.json": mustMarshalJSON(t, map[string]any{
					"@context":   "https://openvex.dev/ns/v0.2.0",
					"@id":        "openvex-first",
					"author":     "author-one",
					"timestamp":  ts,
					"version":    1,
					"statements": []any{},
				}),
				"vex/vex2.json": mustMarshalJSON(t, map[string]any{
					"@context":   "https://openvex.dev/ns/v0.2.0",
					"@id":        "openvex-second",
					"author":     "author-two",
					"timestamp":  ts,
					"version":    1,
					"statements": []any{},
				}),
				"README.md": "# ignore me",
			}), nil
		}

		service := &scanService{}
		reports, err := service.FetchOpenVexFromGitHub(context.Background(), "https://github.com/octo-org/multi-vex-repo", "develop")
		assert.NoError(t, err)
		assert.Len(t, reports, 2)
		assert.Equal(t, "https://github.com/octo-org/multi-vex-repo", reports[0].Source)
		assert.Equal(t, "https://github.com/octo-org/multi-vex-repo", reports[1].Source)
		assert.Equal(t, "openvex-first", reports[0].Report.ID)
		assert.Equal(t, "openvex-second", reports[1].Report.ID)
		assert.Equal(t, "author-one", reports[0].Report.Author)
		assert.Equal(t, "author-two", reports[1].Report.Author)
		assert.Equal(t, 1, calls)
	})

	t.Run("should reject non github urls", func(t *testing.T) {
		service := &scanService{}
		reports, err := service.FetchOpenVexFromGitHub(context.Background(), "https://example.com/repo", "")
		assert.Error(t, err)
		assert.Nil(t, reports)
		assert.Contains(t, err.Error(), "invalid github repository url")
	})
}

func mustMarshalJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal json: %v", err)
	}
	return string(data)
}
