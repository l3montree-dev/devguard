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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
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
			Vulnerability:   models.Vulnerability{},
			Message:         new("Test message"),
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
			Vulnerability:   models.Vulnerability{},
			Message:         new("other message"),
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
			Vulnerability:   models.Vulnerability{},
			Message:         new("Test message"),
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
			Vulnerability:   models.Vulnerability{},
			Message:         new("Another message"),
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

func TestIngestVexFromExternalReferences(t *testing.T) {
	asset := models.Asset{}

	t.Run("does nothing when the SBOM has no exploitability-statement references", func(t *testing.T) {
		externalReferenceRepositoryMock := mocks.NewExternalReferenceRepository(t)
		vexRuleRepositoryMock := mocks.NewVEXRuleRepository(t)

		s := &scanService{
			externalReferenceRepository: externalReferenceRepositoryMock,
			vexRuleRepository:           vexRuleRepositoryMock,
		}

		bom := &cyclonedx.BOM{}

		err := s.IngestVexFromExternalReferences(context.Background(), nil, bom, asset)

		assert.NoError(t, err)
		externalReferenceRepositoryMock.AssertNotCalled(t, "SaveBatch", mock.Anything, mock.Anything, mock.Anything)
		vexRuleRepositoryMock.AssertNotCalled(t, "UpsertBatch", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("fetches and ingests VEX rules when an exploitability-statement reference is present", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mustMarshalJSON(t, map[string]any{
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
			})))
		}))
		defer server.Close()

		vexURL := server.URL + "/component.vex.json"

		externalReferenceRepositoryMock := mocks.NewExternalReferenceRepository(t)
		vexRuleRepositoryMock := mocks.NewVEXRuleRepository(t)
		dependencyVulnRepositoryMock := mocks.NewDependencyVulnRepository(t)

		externalReferenceRepositoryMock.EXPECT().SaveBatch(mock.Anything, mock.Anything, mock.MatchedBy(func(refs []models.ExternalReference) bool {
			ref := refs[0]
			return ref.URL == vexURL && ref.AssetID == asset.ID
		})).Return(nil)

		vexRuleRepositoryMock.EXPECT().FindByAssetID(mock.Anything, mock.Anything, asset.ID).Return(nil, nil)
		vexRuleRepositoryMock.EXPECT().UpsertBatch(mock.Anything, mock.Anything, mock.MatchedBy(func(rules []models.VEXRule) bool {
			return len(rules) == 1
		})).Return(nil)
		dependencyVulnRepositoryMock.EXPECT().GetAllOpenVulnsByAssetID(mock.Anything, mock.Anything, asset.ID, mock.Anything).Return(func(yield func([]models.DependencyVuln, error) bool) {})

		s := &scanService{
			externalReferenceRepository: externalReferenceRepositoryMock,
			vexRuleRepository:           vexRuleRepositoryMock,
			dependencyVulnRepository:    dependencyVulnRepositoryMock,
		}

		refs := []cyclonedx.ExternalReference{
			{Type: cyclonedx.ERTypeExploitabilityStatement, URL: vexURL},
			{Type: cyclonedx.ERTypeOther, URL: "https://example.com/irrelevant"},
		}
		bom := &cyclonedx.BOM{ExternalReferences: &refs}

		err := s.IngestVexFromExternalReferences(context.Background(), nil, bom, asset)

		assert.NoError(t, err)
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
