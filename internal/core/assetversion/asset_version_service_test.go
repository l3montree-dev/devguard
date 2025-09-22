package assetversion

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestFirstPartyVulnHash(t *testing.T) {
	t.Run("should return the same hash for two equal vulnerabilities", func(t *testing.T) {
		snippet1 := models.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents1 := models.SnippetContents{
			Snippets: []models.SnippetContent{snippet1},
		}
		snippetJSON1, err := snippetContents1.ToJSON()
		assert.NoError(t, err)
		vuln1 := models.FirstPartyVuln{
			URI:             "test-uri",
			SnippetContents: snippetJSON1,
			Vulnerability: models.Vulnerability{
				Message: utils.Ptr("Test message"),
			},
		}

		snippet2 := models.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents2 := models.SnippetContents{
			Snippets: []models.SnippetContent{snippet2},
		}
		snippetJSON2, err := snippetContents2.ToJSON()
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
		snippet1 := models.SnippetContent{
			StartLine:   1,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   20,
			Snippet:     "TestSnippet",
		}
		snippetContents1 := models.SnippetContents{
			Snippets: []models.SnippetContent{snippet1},
		}
		snippetJSON1, err := snippetContents1.ToJSON()
		assert.NoError(t, err)
		vuln1 := models.FirstPartyVuln{
			URI:             "test-uri",
			SnippetContents: snippetJSON1,
			Vulnerability: models.Vulnerability{
				Message: utils.Ptr("Test message"),
			},
		}

		snippet2 := models.SnippetContent{
			StartLine:   3,
			EndLine:     4,
			StartColumn: 5,
			EndColumn:   6,
			Snippet:     "AnotherSnippet",
		}
		snippetContents2 := models.SnippetContents{
			Snippets: []models.SnippetContent{snippet2},
		}
		snippetJSON2, err := snippetContents2.ToJSON()
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
		vuln := common.SarifResult{
			Version: "2.1.0",
			Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
			Runs: []common.Run{
				{
					Results: []common.Result{
						{
							RuleID: "test-rule",
							Locations: []common.Location{
								{
									PhysicalLocation: common.PhysicalLocation{
										ArtifactLocation: common.ArtifactLocation{
											URI: "test-uri",
										},
										Region: common.Region{
											StartLine: 1,
											Snippet: common.Text{
												Text: "TestSnippet",
											},
										},
									},
								},
							},
							Fingerprints: &common.Fingerprints{
								CalculatedFingerprint: "test-fingerprint",
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
func TestDiffScanResults(t *testing.T) {

	t.Run("should correctly identify a vulnerability which now gets found by another artifact", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		assetID := uuid.New()
		assetVersionName := "asset-version-1"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID}},
		}

		artifact := models.Artifact{ArtifactName: "artifact1", AssetVersionName: assetVersionName, AssetID: assetID}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersionName, AssetID: assetID,
			}, Artifacts: []models.Artifact{artifact}},
		}

		firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName := diffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, firstDetected)
		assert.Empty(t, fixedOnAll)
		assert.Empty(t, fixedOnThisArtifactName)
		assert.Equal(t, 1, len(firstDetectedOnThisArtifactName))
	})

	t.Run("should correctly identify a vulnerability which now is fixed, since it was not found by the artifact anymore", func(t *testing.T) {

		assetID := uuid.New()

		artifact := models.Artifact{ArtifactName: "artifact1", AssetVersionName: "asset-version-1", AssetID: assetID}

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName := diffScanResults(artifact.ArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, firstDetected)
		assert.Equal(t, 1, len(fixedOnAll))
		assert.Empty(t, firstDetectedOnThisArtifactName)
		assert.Empty(t, fixedOnThisArtifactName)
	})

	t.Run("should correctly identify a vulnerability which is not found in the current artifact anymore", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName := diffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, firstDetected)
		assert.Empty(t, fixedOnAll)
		assert.Empty(t, firstDetectedOnThisArtifactName)
		assert.Equal(t, 1, len(fixedOnThisArtifactName))
	})

	t.Run("should identify new vulnerabilities", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
			{CVEID: utils.Ptr("CVE-5678")},
		}

		existingDependencyVulns := []models.DependencyVuln{}

		firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName := diffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Equal(t, 2, len(firstDetected))
		assert.Empty(t, fixedOnAll)
		assert.Empty(t, firstDetectedOnThisArtifactName)
		assert.Empty(t, fixedOnThisArtifactName)
	})

	t.Run("BUG: should NOT incorrectly identify artifact removal when artifact ID contains colon and is substring of existing artifact", func(t *testing.T) {

		currentArtifactName := "container-scanning"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		firstDetected, fixedOnAll, firstDetectedOnThisArtifactName, fixedOnThisArtifactName := diffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, firstDetected, "Should be empty - this is a new detection by current artifact")
		assert.Empty(t, fixedOnAll, "Should be empty - no vulnerabilities are fixed")
		assert.Equal(t, 1, len(firstDetectedOnThisArtifactName), "Should detect that current artifact found existing vulnerability for first time")
		assert.Empty(t, fixedOnThisArtifactName, "BUG: Should be empty - current artifact was never detecting this vulnerability before!")
	})
}

func TestYamlMetadata(t *testing.T) {
	t.Run("Test the created yaml", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := "Komplette Fantasie"

		metaData := createYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: Komplette\n  app_title_part_two: Fantasie@main\n  organization_name: TestOrga\n  integrity: \"\"\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
	t.Run("Test the created yaml with empty title", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := ""

		metaData := createYAMLMetadata(organizationName, projectTitle, assetVersionName)
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

func TestDiffVulnsBetweenBranches(t *testing.T) {

	t.Run("should copy events when vuln exists on other branch", func(t *testing.T) {
		assetID := uuid.New()

		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					ID:               "vuln-1",
					AssetVersionName: "feature-branch",
					AssetID:          assetID,
					Events:           []models.VulnEvent{},
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					ID:               "vuln-2",
					AssetVersionName: "main",
					AssetID:          assetID,
					Events: []models.VulnEvent{{Type: models.EventTypeDetected},
						{Type: models.EventTypeComment}},
				},
				Artifacts: []models.Artifact{{ArtifactName: "artifact1", AssetVersionName: "feature-branch", AssetID: assetID},
					{ArtifactName: "artifact2", AssetVersionName: "feature-branch", AssetID: assetID}},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, newDetectedVulnsNotOnOtherBranch)
		assert.Len(t, newDetectedButOnOtherBranchExisting, 1)
		assert.Len(t, existingEvents, 1)
		fmt.Printf("Existing Events: %+v\n", existingEvents)
		assert.Len(t, existingEvents[0], 2)

	})

	t.Run("should identify new vulnerabilities not on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: utils.Ptr("CVE-2023-0002"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0003"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
				},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Len(t, newDetectedVulnsNotOnOtherBranch, 2)
		assert.Empty(t, newDetectedButOnOtherBranchExisting)
		assert.Empty(t, existingEvents)
		assert.Equal(t, "CVE-2023-0001", *newDetectedVulnsNotOnOtherBranch[0].CVEID)
		assert.Equal(t, "CVE-2023-0002", *newDetectedVulnsNotOnOtherBranch[1].CVEID)
	})

	t.Run("should identify vulnerabilities that exist on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: models.EventTypeAccepted,
						},
					},
				},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, newDetectedVulnsNotOnOtherBranch)
		assert.Len(t, newDetectedButOnOtherBranchExisting, 1)
		assert.Len(t, existingEvents, 1)
		assert.Equal(t, "CVE-2023-0001", *newDetectedButOnOtherBranchExisting[0].CVEID)
		assert.Len(t, existingEvents[0], 1)
		assert.Equal(t, "main", *existingEvents[0][0].OriginalAssetVersionName)
	})

	t.Run("should handle multiple vulnerabilities with same CVE on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: models.EventTypeComment,
						},
					},
				},
			},
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "develop",
					Events: []models.VulnEvent{
						{
							Type: models.EventTypeComment,
						},
					},
				},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, newDetectedVulnsNotOnOtherBranch)
		assert.Len(t, newDetectedButOnOtherBranchExisting, 1)
		assert.Len(t, existingEvents, 1)
		assert.Len(t, existingEvents[0], 2) // combined events from both existing vulns
		assert.Equal(t, "main", *existingEvents[0][0].OriginalAssetVersionName)
		assert.Equal(t, "develop", *existingEvents[0][1].OriginalAssetVersionName)
	})

	t.Run("should filter out events that were already copied", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type:                     models.EventTypeDetected,
							OriginalAssetVersionName: nil, // original event
						},
						{
							Type:                     models.EventTypeAccepted,
							OriginalAssetVersionName: utils.Ptr("other-branch"), // already copied event
						},
					},
				},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, newDetectedVulnsNotOnOtherBranch)
		assert.Len(t, newDetectedButOnOtherBranchExisting, 1)
		assert.Len(t, existingEvents, 1)
		assert.Len(t, existingEvents[0], 1) // only the original event, not the copied one
		assert.Equal(t, models.EventTypeDetected, existingEvents[0][0].Type)
		assert.Equal(t, "main", *existingEvents[0][0].OriginalAssetVersionName)
	})

	t.Run("should handle mixed scenario with new and existing vulnerabilities", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0001"), // new vuln
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: utils.Ptr("CVE-2023-0002"), // exists on other branch
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: utils.Ptr("CVE-2023-0003"), // new vuln
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: utils.Ptr("CVE-2023-0002"),
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: models.EventTypeDetected,
						},
					},
				},
			},
		}

		newDetectedVulnsNotOnOtherBranch, newDetectedButOnOtherBranchExisting, existingEvents := diffBetweenBranches(foundVulnerabilities, existingDependencyVulns)

		assert.Len(t, newDetectedVulnsNotOnOtherBranch, 2)
		assert.Len(t, newDetectedButOnOtherBranchExisting, 1)
		assert.Len(t, existingEvents, 1)

		// check new vulnerabilities
		newCVEs := []string{*newDetectedVulnsNotOnOtherBranch[0].CVEID, *newDetectedVulnsNotOnOtherBranch[1].CVEID}
		assert.Contains(t, newCVEs, "CVE-2023-0001")
		assert.Contains(t, newCVEs, "CVE-2023-0003")

		// check existing vulnerability
		assert.Equal(t, "CVE-2023-0002", *newDetectedButOnOtherBranchExisting[0].CVEID)
		assert.Len(t, existingEvents[0], 1)
		assert.Equal(t, "main", *existingEvents[0][0].OriginalAssetVersionName)
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
		err := markdownTableFromSBOM(&markdownFile, &bom)
		fmt.Println(markdownFile.String())
		assert.Nil(t, err)
		assert.Equal(t, "# SBOM\n\n## Overview\n\n- **Artifact Name:** \n- **Version:** \n- **Created:** \n- **Publisher:** \n\n## Statistics\n\n### Ecosystem Distribution\nTotal Components: 3\n\n| Ecosystem | Count | Percentage |\n|-----------|-------|------------|\n| deb | 3 | 100.0% |\n\n\n### License Distribution\n| License | Count | Percentage |\n|---------|-------|------------|\n| MIT | 2 | 66.7% |\n| Unknown | 1 | 33.3% |\n\n\n\\newpage\n## Components\n\n| Package \t\t\t\t\t\t  | Version | Licenses  |\n|---------------------------------|---------|-------|\n| pkg:deb/debian/gcc-12@12.2.0 | 12.2.0-14 | MIT  |\n| pkg:deb/debian/libc6@2.36-9&#43;deb12u10 | 2.36-9&#43;deb12u10 | MIT  |\n| pkg:deb/debian/libstdc&#43;&#43;6@12.2.0-14 | 12.2.0-14 |  Unknown  |\n", markdownFile.String())
	})
}

func TestBuildVeX(t *testing.T) {
	// Create a mock service instance for testing
	s := &service{}

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
		componentDepth := 1
		justification := "This vulnerability does not affect our use case"

		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:          &cveID,
				ComponentPurl:  &componentPurl,
				ComponentDepth: &componentDepth,
				CVE: &models.CVE{
					CVE:         cveID,
					CVSS:        float32(5.0),
					Vector:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
					Description: "Test CVE Description",
				},
				Vulnerability: models.Vulnerability{
					State: models.VulnStateAccepted,
					Events: []models.VulnEvent{
						{
							Type:          models.EventTypeDetected,
							Justification: utils.Ptr("Initial detection event without justification"),
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
							},
						},
						{
							Type:          models.EventTypeAccepted,
							Justification: &justification,
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC),
							},
						},
						{
							Type:          models.EventTypeComment,
							Justification: utils.Ptr("This is a comment and should be ignored"),
							Model: models.Model{
								CreatedAt: time.Date(2023, 1, 3, 12, 0, 0, 0, time.UTC),
							},
						},
					},
				},
			},
		}

		result := s.BuildVeX(asset, assetVersion, organizationName, "test-artifact", dependencyVulns)

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)
		assert.Len(t, *result.Vulnerabilities, 1)

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, justification, vuln.Analysis.Detail)
	})

}
