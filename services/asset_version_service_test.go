package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_4,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "pkg:generic/my-artifact@1.0.0",
					Name:   "my-artifact",
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
		assert.Equal(t, "# SBOM\n\n## Overview\n\n- **Artifact Name:** my-artifact\n- **Version:** \n- **Created:** \n- **Publisher:** \n\n## Statistics\n\n### Ecosystem Distribution\nTotal Components: 3\n\n| Ecosystem | Count | Percentage |\n|-----------|-------|------------|\n| deb | 3 | 100.0% |\n\n\n### License Distribution\n| License | Count | Percentage |\n|---------|-------|------------|\n| MIT | 2 | 66.7% |\n| Unknown | 1 | 33.3% |\n\n\n\\newpage\n## Components\n\n| Package \t\t\t\t\t\t  | Version | Licenses  |\n|---------------------------------|---------|-------|\n| pkg:deb/debian/gcc-12@12.2.0 | 12.2.0-14 | MIT  |\n| pkg:deb/debian/libc6@2.36-9&#43;deb12u10 | 2.36-9&#43;deb12u10 | MIT  |\n| pkg:deb/debian/libstdc&#43;&#43;6@12.2.0-14 | 12.2.0-14 |  Unknown  |\n", markdownFile.String())
	})
}

// buildVeXTestService creates an assetVersionService with a mocked VEXRuleService
// that returns the given rules for any FindByAssetVersion call.
func buildVeXTestService(t *testing.T, rules []models.VEXRule) *assetVersionService {
	vexRuleService := mocks.NewVEXRuleService(t)
	vexRuleService.On("FindByAssetVersion", mock.Anything, mock.Anything, mock.Anything).Return(rules, nil)
	return &assetVersionService{vexRuleService: vexRuleService}
}

func TestBuildVeX(t *testing.T) {
	t.Run("two dependency vulns with same CVE and component but different paths are deduplicated", func(t *testing.T) {
		s := buildVeXTestService(t, nil)
		asset := models.Asset{
			Model: models.Model{ID: uuid.New()},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: asset.ID,
			Slug:    "v1-0-0",
		}

		cveID := "ALPINE-CVE-2026-24515"
		componentPurl := "pkg:apk/alpine/libexpat@2.7.3-r0?arch=x86_64&distro=3.22.2"

		// Two vulns with the same CVE and component but different vulnerability paths.
		// VulnerabilityPath is not used in VEX output — only ComponentPurl goes into Affects.
		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{"pkg:oci/my-image@sha256:abc", componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   7.5,
					Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
			},
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{"pkg:oci/another-image@sha256:def", componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   7.5,
					Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
			},
		}

		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)

		// Vulns with the same CVE ID + Affects + State are deduplicated by SBOMGraph.AddVulnerability.
		// The map key is: vuln.ID + "@" + affectsStr + "@" + state
		// Since both vulns have the same CVE, same ComponentPurl, and same state,
		// only ONE vulnerability entry appears in the output.
		assert.Len(t, *result.Vulnerabilities, 1,
			"Vulns with same CVE+Affects+State are deduplicated — VulnerabilityPath is not in the key")

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, cveID, vuln.ID)
		assert.NotNil(t, vuln.Affects)
		assert.Len(t, *vuln.Affects, 1)
		assert.Equal(t, componentPurl, (*vuln.Affects)[0].Ref)
	})

	t.Run("should handle justification from events", func(t *testing.T) {
		s := buildVeXTestService(t, nil)
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

	t.Run("accepted (exploitable) state wins over open (in_triage) state for same CVE", func(t *testing.T) {
		s := buildVeXTestService(t, nil)
		asset := models.Asset{
			Model: models.Model{ID: uuid.New()},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: asset.ID,
			Slug:    "v1-0-0",
		}

		cveID := "CVE-2024-STATE-PRIORITY"
		componentPurl := "pkg:npm/lib@1.0.0"

		// Two vulns with same CVE and component but different states:
		// One is open (in_triage), one is accepted (exploitable)
		// The accepted state should win because it means the vuln is confirmed exploitable
		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   7.5,
					Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
			},
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   7.5,
					Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateAccepted,
					Events: []models.VulnEvent{{
						Type:          dtos.EventTypeAccepted,
						Justification: utils.Ptr("Risk accepted"),
						Model:         models.Model{CreatedAt: time.Now()},
					}},
				},
			},
		}

		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)

		// Should be deduplicated to ONE vulnerability with the winning state
		assert.Len(t, *result.Vulnerabilities, 1,
			"Same CVE+Affects should be deduplicated to one entry with priority state")

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, cveID, vuln.ID)
		// Accepted = exploitable should win over open = in_triage
		assert.Equal(t, cdx.IASExploitable, vuln.Analysis.State,
			"Accepted (exploitable) state should win over open (in_triage)")
	})

	t.Run("open (in_triage) state wins over false_positive when at least one is open", func(t *testing.T) {
		s := buildVeXTestService(t, nil)
		asset := models.Asset{
			Model: models.Model{ID: uuid.New()},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: asset.ID,
			Slug:    "v1-0-0",
		}

		cveID := "CVE-2024-OPEN-WINS"
		componentPurl := "pkg:npm/lib@1.0.0"

		// Two vulns: one false_positive, one open
		// Open should win because at least one occurrence needs triage
		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFalsePositive,
					Events: []models.VulnEvent{{
						Type:          dtos.EventTypeFalsePositive,
						Justification: utils.Ptr("Not affected in this context"),
						Model:         models.Model{CreatedAt: time.Now()},
					}},
				},
			},
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
			},
		}

		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)

		assert.Len(t, *result.Vulnerabilities, 1,
			"Same CVE+Affects should be deduplicated to one entry")

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, cveID, vuln.ID)
		// Open = in_triage should win over false_positive
		assert.Equal(t, cdx.IASInTriage, vuln.Analysis.State,
			"Open (in_triage) state should win over false_positive when at least one is open")
	})

	t.Run("false_positive state only when ALL occurrences are false_positive", func(t *testing.T) {
		s := buildVeXTestService(t, nil)
		asset := models.Asset{
			Model: models.Model{ID: uuid.New()},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: asset.ID,
			Slug:    "v1-0-0",
		}

		cveID := "CVE-2024-ALL-FP"
		componentPurl := "pkg:npm/lib@1.0.0"

		// Two vulns both marked as false_positive
		// Result should be false_positive since ALL are false_positive
		dependencyVulns := []models.DependencyVuln{
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{"pkg:npm/app@1.0.0", componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFalsePositive,
					Events: []models.VulnEvent{{
						Type:          dtos.EventTypeFalsePositive,
						Justification: utils.Ptr("Not affected via path 1"),
						Model:         models.Model{CreatedAt: time.Now()},
					}},
				},
			},
			{
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{"pkg:npm/other-app@2.0.0", componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFalsePositive,
					Events: []models.VulnEvent{{
						Type:          dtos.EventTypeFalsePositive,
						Justification: utils.Ptr("Not affected via path 2"),
						Model:         models.Model{CreatedAt: time.Now()},
					}},
				},
			},
		}

		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		assert.NotNil(t, result)
		assert.NotNil(t, result.Vulnerabilities)

		assert.Len(t, *result.Vulnerabilities, 1,
			"Same CVE+Affects should be deduplicated to one entry")

		vuln := (*result.Vulnerabilities)[0]
		assert.Equal(t, cveID, vuln.ID)
		// All false_positive = result should be false_positive
		assert.Equal(t, cdx.IASFalsePositive, vuln.Analysis.State,
			"False positive state should be used when ALL occurrences are false_positive")
	})

	t.Run("includes pathPattern properties from matching VEX rules", func(t *testing.T) {
		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: assetID,
			Slug:    "v1-0-0",
		}

		cveID := "CVE-2024-PATH"
		vulnID := "vuln-path-1"
		componentPurl := "pkg:golang/vulnerable-lib@v1.0"
		pathPattern := dtos.PathPattern{"pkg:golang/myapp@v1.0", dtos.PathPatternWildcard, componentPurl}

		// VEX rule that matches this vuln
		rules := []models.VEXRule{
			{
				CVEID:       cveID,
				PathPattern: pathPattern,
				Enabled:     true,
				EventType:   dtos.EventTypeFalsePositive,
			},
		}

		dependencyVulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					ID:    vulnID,
					State: dtos.VulnStateFalsePositive,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{"pkg:golang/myapp@v1.0", "pkg:golang/mid@v1.0", componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
			},
		}

		s := buildVeXTestService(t, rules)
		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		require.NotNil(t, result)
		require.NotNil(t, result.Vulnerabilities)
		require.Len(t, *result.Vulnerabilities, 1)

		vuln := (*result.Vulnerabilities)[0]
		require.NotNil(t, vuln.Properties, "vulnerability should have properties with pathPattern")
		require.Len(t, *vuln.Properties, 1)

		prop := (*vuln.Properties)[0]
		assert.Equal(t, "devguard:pathPattern", prop.Name)

		// The value should be the JSON-marshalled path pattern
		expectedJSON, _ := json.Marshal(pathPattern)
		assert.Equal(t, string(expectedJSON), prop.Value)
	})

	t.Run("no pathPattern properties when no VEX rules match", func(t *testing.T) {
		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
			Slug:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: assetID,
			Slug:    "v1-0-0",
		}

		cveID := "CVE-2024-NOMATCH"
		componentPurl := "pkg:golang/lib@v1.0"

		dependencyVulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					ID:    "vuln-no-match",
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{{
						Type:  dtos.EventTypeDetected,
						Model: models.Model{CreatedAt: time.Now()},
					}},
				},
				CVEID:             cveID,
				ComponentPurl:     componentPurl,
				VulnerabilityPath: []string{componentPurl},
				CVE: models.CVE{
					CVE:    cveID,
					CVSS:   5.0,
					Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
				},
			},
		}

		s := buildVeXTestService(t, nil)
		result := s.BuildVeX("", "test-org", "", "", asset, assetVersion, "test-artifact", dependencyVulns).ToCycloneDX(normalize.BOMMetadata{})

		require.NotNil(t, result)
		require.NotNil(t, result.Vulnerabilities)
		require.Len(t, *result.Vulnerabilities, 1)

		vuln := (*result.Vulnerabilities)[0]
		assert.Nil(t, vuln.Properties, "vulnerability should have no properties when no rules match")
	})
}
