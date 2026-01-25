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
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
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
				Message: utils.Ptr("Test message"),
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
				Message: utils.Ptr("other message"),
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
				Message: utils.Ptr("Test message"),
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
				Message: utils.Ptr("Another message"),
			},
		}

		assert.NotEqual(t, vuln1.CalculateHash(), vuln2.CalculateHash())
	})

	t.Run("should take the hash of the vulnerability, if it exists", func(t *testing.T) {
		vuln := sarif.SarifSchema210Json{
			Version: "2.1.0",
			Schema:  utils.Ptr("https://json.schemastore.org/sarif-2.1.0.json"),
			Runs: []sarif.Run{
				{
					Results: []sarif.Result{
						{
							RuleID: utils.Ptr("test-rule"),
							Locations: []sarif.Location{
								{
									PhysicalLocation: sarif.PhysicalLocation{
										ArtifactLocation: sarif.ArtifactLocation{
											URI: utils.Ptr("test-uri"),
										},
										Region: &sarif.Region{
											StartLine: utils.Ptr(1),
											Snippet: &sarif.ArtifactContent{

												Text: utils.Ptr("TestSnippet"),
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
				ID: "test-fingerprint", // this should match the fingerprint
			},
			Fingerprint: "test-fingerprint",
		}

		// set up the mock expectation
		scanService.On("HandleFirstPartyVulnResult",
			models.Org{},
			models.Project{},
			models.Asset{},
			&models.AssetVersion{Name: "test-asset-version"},
			vuln,
			"scannerID",
			"userID").Return([]models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{expectedVuln}, nil)

		_, _, r, err := scanService.HandleFirstPartyVulnResult(
			models.Org{},
			models.Project{},
			models.Asset{},
			&models.AssetVersion{
				Name: "test-asset-version",
			},
			vuln,
			"scannerID",
			"userID")
		assert.NoError(t, err)
		assert.Len(t, r, 1)
		assert.Equal(t, "test-fingerprint", r[0].ID)
	})

}
