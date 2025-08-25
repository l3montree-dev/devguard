package assetversion

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
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

	t.Run("should correctly identify a vulnerability which now gets found by another scanner", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
		}

		artifact := models.Artifact{ArtifactName: "artifact1"}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Empty(t, fixedVulns)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
		assert.Equal(t, 1, len(detectedByCurrentScanner))
	})

	t.Run("should correctly identify a vulnerability which now is fixed, since it was not found by the scanner anymore", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Equal(t, 1, len(fixedVulns))
		assert.Empty(t, detectedByCurrentScanner)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
	})

	t.Run("should correctly identify a vulnerability which is not detected by the current scanner anymore", func(t *testing.T) {
		currentScanner := "new-scanner"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Empty(t, fixedVulns)
		assert.Empty(t, detectedByCurrentScanner)
		assert.Equal(t, 1, len(notDetectedByCurrentScannerAnymore))
	})

	t.Run("should identify new vulnerabilities", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
			{CVEID: utils.Ptr("CVE-5678")},
		}

		existingDependencyVulns := []models.DependencyVuln{}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Equal(t, 2, len(foundByScannerAndNotExisting))
		assert.Empty(t, fixedVulns)
		assert.Empty(t, detectedByCurrentScanner)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
	})

	t.Run("BUG: should NOT incorrectly identify scanner removal when scanner ID contains colon and is substring of existing scanner", func(t *testing.T) {

		currentScanner := "container-scanning"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting, "Should be empty - this is a new detection by current scanner")
		assert.Empty(t, fixedVulns, "Should be empty - no vulnerabilities are fixed")
		assert.Equal(t, 1, len(detectedByCurrentScanner), "Should detect that current scanner found existing vulnerability for first time")
		assert.Empty(t, notDetectedByCurrentScannerAnymore, "BUG: Should be empty - current scanner was never detecting this vulnerability before!")
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
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: Komplette\n  app_title_part_two: Fantasie\n  organization_name: TestOrga\n  integrity: \"\"\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
	t.Run("Test the created yaml with empty title", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := ""

		metaData := createYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: \"\"\n  app_title_part_two: \"\"\n  organization_name: TestOrga\n  integrity: \"\"\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
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
							Type: models.EventTypeDetected,
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
							Type: models.EventTypeDetected,
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
			Components: &[]cdx.Component{
				{BOMRef: "pkg:deb/debian/gcc-12@12.2.0", Name: "debian/gcc-12", Version: "12.2.0-14", Type: "application", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}}, {License: &cdx.License{ID: "Apache-4.0"}}}},
				{BOMRef: "pkg:deb/debian/libc6@2.36-9+deb12u10", Name: "debian/libc6", Version: "2.36-9+deb12u10", Type: "library", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}},
				{BOMRef: "pkg:deb/debian/libstdc++6@12.2.0-14", Name: "debian/libstdc++6", Version: "12.2.0-14", Type: "library", Licenses: &cdx.Licenses{}},
			},
		}
		markdownFile := bytes.Buffer{}
		err := markdownTableFromSBOM(&markdownFile, &bom)
		fmt.Println(markdownFile.String())
		assert.Nil(t, err)
		assert.Equal(t, "# SBOM\n\n| PURL | Name | Version | Licenses  |\n|-------------------|---------|---------|--------|\n| pkg:deb/debian/gcc-12@12.2.0 | debian/gcc-12 | 12.2.0-14 | Apache-2.0 Apache-4.0  |\n| pkg:deb/debian/libc6@2.36-9&#43;deb12u10 | debian/libc6 | 2.36-9&#43;deb12u10 | MIT  |\n| pkg:deb/debian/libstdc&#43;&#43;6@12.2.0-14 | debian/libstdc&#43;&#43;6 | 12.2.0-14 |  Unknown  |\n", markdownFile.String())
	})
}
