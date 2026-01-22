package services

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
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

		assetVersionService := mocks.NewAssetVersionService(t)

		// create the expected FirstPartyVuln with the fingerprint
		// the ID should be set to the fingerprint when it exists
		expectedVuln := models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				ID: "test-fingerprint", // this should match the fingerprint
			},
			Fingerprint: "test-fingerprint",
		}

		// set up the mock expectation
		assetVersionService.On("HandleFirstPartyVulnResult",
			models.Org{},
			models.Project{},
			models.Asset{},
			&models.AssetVersion{Name: "test-asset-version"},
			vuln,
			"scannerID",
			"userID").Return([]models.FirstPartyVuln{}, []models.FirstPartyVuln{}, []models.FirstPartyVuln{expectedVuln}, nil)

		_, _, r, err := assetVersionService.HandleFirstPartyVulnResult(
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

func TestYamlMetadata(t *testing.T) {
	t.Run("Test the created yaml", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := "Komplette Fantasie"

		metaData := CreateYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: Komplette\n  app_title_part_two: Fantasie@main\n  organization_name: TestOrga\n  integrity: \"\"\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
	t.Run("Test the created yaml with empty title", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := ""

		metaData := CreateYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: '@main'\n  app_title_part_two: \"\"\n  organization_name: TestOrga\n  integrity: \"\"\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
}

func TestCreateProjectTitle(t *testing.T) {
	t.Run("empty project name should return two empty titles", func(t *testing.T) {
		projectTitle := ""
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "", title1, title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name <= 14 characters should just return project name in title1 and title2 should be empty", func(t *testing.T) {
		projectTitle := "One Two Fields"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, projectTitle, title1)
		assert.Equal(t, "", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 14 characters and <= 28 characters should split up the name at the optimal whitespace", func(t *testing.T) {
		projectTitle := "One Two Three Four Fields"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Fields", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields < 14 should cut off after the titles are full", func(t *testing.T) {
		projectTitle := "One Two Three Four Fields More Fields?"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Fields", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields < 14 should cut off the last title", func(t *testing.T) {
		projectTitle := "One Two Three Four Taco Fields More Fields?"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Taco Fi..", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields > 14 should cut off first title with a -, not enough space for api so it gets left out", func(t *testing.T) {
		projectTitle := "WhoWouldUseSuchALongName Api"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "WhoWouldUseSu-", title1)
		assert.Equal(t, "chALongName", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields > 14 should cut off first title with a -, enough space for api so it gets inserted", func(t *testing.T) {
		projectTitle := "WhoWouldUseSuchLongName Api"
		title1, title2 := createTitles(projectTitle)
		assert.Equal(t, "WhoWouldUseSu-", title1)
		assert.Equal(t, "chLongName Api", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
}

func TestMarkdownTableFromSBOM(t *testing.T) {
	t.Run("test an sbom with 3 components which have 2 , 1 and 0 licenses respectively ", func(t *testing.T) {
		bom := cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "pkg:generic/my-artifact@1.0.0",
				},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:deb/debian/gcc-12@12.2.0", PackageURL: "pkg:deb/debian/gcc-12@12.2.0", Version: "12.2.0-14", Type: "application", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}},
				{BOMRef: "pkg:deb/debian/libc6@2.36-9+deb12u10", PackageURL: "pkg:deb/debian/libc6@2.36-9+deb12u10", Version: "2.36-9+deb12u10", Type: "library", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}},
				{BOMRef: "pkg:deb/debian/libstdc++6@12.2.0-14", PackageURL: "pkg:deb/debian/libstdc++6@12.2.0-14", Version: "12.2.0-14", Type: "library", Licenses: &cdx.Licenses{}},
			},
		}
		markdownFile := bytes.Buffer{}
		err := MarkdownTableFromSBOM(&markdownFile, &bom)
		fmt.Println(markdownFile.String())
		assert.Nil(t, err)
		assert.Equal(t, "# SBOM\n\n## Overview\n\n- **Artifact Name:** \n- **Version:** \n- **Created:** \n- **Publisher:** \n\n## Statistics\n\n### Ecosystem Distribution\nTotal Components: 3\n\n| Ecosystem | Count | Percentage |\n|-----------|-------|------------|\n| deb | 3 | 100.0% |\n\n\n### License Distribution\n| License | Count | Percentage |\n|---------|-------|------------|\n| MIT | 2 | 66.7% |\n| Unknown | 1 | 33.3% |\n\n\n\\newpage\n## Components\n\n| Package \t\t\t\t\t\t  | Version | Licenses  |\n|---------------------------------|---------|-------|\n| pkg:deb/debian/gcc-12@12.2.0 | 12.2.0-14 | MIT  |\n| pkg:deb/debian/libc6@2.36-9&#43;deb12u10 | 2.36-9&#43;deb12u10 | MIT  |\n| pkg:deb/debian/libstdc&#43;&#43;6@12.2.0-14 | 12.2.0-14 |  Unknown  |\n", markdownFile.String())
	})
}

func TestBuildVeX(t *testing.T) {
	// Create a mock assetVersionService instance for testing
	s := &assetVersionService{}

	t.Run("should handle justification from events", func(t *testing.T) {
		asset := models.Asset{
			Model: models.Model{
				ID: uuid.New(),
			},
			Name: "test-asset",
			Slug: "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: asset.ID,
			Slug:    "v1-0-0",
		}
		organizationName := "test-org"

		cveID := "CVE-2023-12345"
		componentPurl := "pkg:npm/test-component@1.0.0"
		justification := "This vulnerability does not affect our use case"

		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:         cveID,
				ComponentPurl: componentPurl,
				CVE: models.CVE{
					CVE:         cveID,
					CVSS:        float32(5.0),
					Vector:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
					Description: "Test CVE Description",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateAccepted,
					Events: []models.VulnEvent{
						{
							Type:          dtos.EventTypeDetected,
							Justification: utils.Ptr("Initial detection event without justification"),
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
							},
						},
						{
							Type:          dtos.EventTypeAccepted,
							Justification: &justification,
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC),
							},
						},
						{
							Type:          dtos.EventTypeComment,
							Justification: utils.Ptr("This is a comment and should be ignored"),
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 3, 12, 0, 0, 0, time.UTC),
							},
						},
					},
				},
			},
		}

		result := s.BuildVeX("", organizationName, "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)
		assert.Len(t, *result.Vulnerabilities, 1)

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, justification, vuln.Analysis.Detail)
	})
}
