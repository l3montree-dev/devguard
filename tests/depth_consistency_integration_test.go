package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// TestDepthConsistencyAcrossMultipleArtifacts verifies that:
// 1. When the same vulnerability exists in multiple artifacts at different depths, the minimum depth is used
// 2. When the artifact with minimum depth is deleted, depths are recalculated from remaining artifacts
func TestDepthConsistencyAcrossMultipleArtifacts(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Setup: Create CVE and affected component
		cve := models.CVE{
			CVE:    "CVE-2024-DEPTH-TEST",
			CVSS:   5.5,
			Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		}
		f.DB.Create(&cve)

		affectedComponent := models.AffectedComponent{
			PurlWithoutVersion: "pkg:npm/vulnerable-lib",
			Scheme:             "pkg",
			Type:               "npm",
			Name:               "vulnerable-lib",
			Namespace:          utils.Ptr(""),
			SemverFixed:        utils.Ptr("2.0.0"),
		}
		f.DB.Create(&affectedComponent)
		err := f.DB.Model(&cve).Association("AffectedComponents").Append(&affectedComponent)
		assert.NoError(t, err)

		// Create test asset with environmental requirements
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ConfidentialityRequirement = dtos.RequirementLevel("high")
		asset.IntegrityRequirement = dtos.RequirementLevel("high")
		asset.AvailabilityRequirement = dtos.RequirementLevel("high")
		f.DB.Save(&asset)

		// Helper to create scan request
		scan := func(artifactName string, depth int) dtos.ScanResponse {
			// Build simple SBOM with vulnerable component at specified depth
			components := []cdx.Component{{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "vulnerable-lib",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/vulnerable-lib@1.0.0",
				BOMRef:     "pkg:npm/vulnerable-lib@1.0.0",
			}}

			if depth == 2 {
				components = append([]cdx.Component{{
					Type:       cdx.ComponentTypeLibrary,
					Name:       "intermediate-lib",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/intermediate-lib@1.0.0",
					BOMRef:     "pkg:npm/intermediate-lib@1.0.0",
				}}, components...)
			}

			rootRef := "pkg:npm/test-app@1.0.0"
			deps := []cdx.Dependency{{Ref: rootRef}}
			if depth == 1 {
				deps[0].Dependencies = &[]string{"pkg:npm/vulnerable-lib@1.0.0"}
			} else {
				deps[0].Dependencies = &[]string{"pkg:npm/intermediate-lib@1.0.0"}
				deps = append(deps, cdx.Dependency{
					Ref:          "pkg:npm/intermediate-lib@1.0.0",
					Dependencies: &[]string{"pkg:npm/vulnerable-lib@1.0.0"},
				})
			}

			bom := cdx.BOM{
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_6,
				Version:     1,
				Metadata: &cdx.Metadata{
					Component: &cdx.Component{
						BOMRef:     rootRef,
						Type:       cdx.ComponentTypeApplication,
						Name:       "test-app",
						Version:    "1.0.0",
						PackageURL: rootRef,
					},
				},
				Components:   &components,
				Dependencies: &deps,
			}

			var buf bytes.Buffer
			assert.Nil(t, cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(&bom))

			app := echo.New()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &buf)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user").Maybe()
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
			ctx.Request().Header.Set("X-Artifact-Name", artifactName)
			ctx.Request().Header.Set("X-Asset-Default-Branch", "main")
			ctx.Request().Header.Set("X-Asset-Ref", assetVersion.Name)

			err := f.App.ScanController.ScanDependencyVulnFromProject(ctx)
			assert.NoError(t, err)

			var response dtos.ScanResponse
			err = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			return response
		}

		// Step 1: Scan artifact at depth 2
		scan("source", 2)
		var vuln models.DependencyVuln
		f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2024-DEPTH-TEST", asset.ID).First(&vuln)
		assert.Equal(t, 2, *vuln.ComponentDepth, "Initial depth should be 2")
		risk1 := *vuln.RawRiskAssessment

		// Step 2: Scan same vuln at depth 1 - should use minimum
		scan("scanner", 1)
		f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2024-DEPTH-TEST", asset.ID).First(&vuln)
		assert.Equal(t, 1, *vuln.ComponentDepth, "Depth should update to minimum (1)")
		risk2 := *vuln.RawRiskAssessment
		assert.Greater(t, risk2, risk1, "Risk should be higher at depth 1")

		// Step 3: Run pipeline - depth should remain stable
		err = f.App.DaemonRunner.RunDaemonPipelineForAsset(asset.ID)
		assert.NoError(t, err)
		f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2024-DEPTH-TEST", asset.ID).First(&vuln)
		assert.Equal(t, 1, *vuln.ComponentDepth, "Depth should remain at 1 after pipeline")
		assert.Equal(t, risk2, *vuln.RawRiskAssessment, "Risk should remain consistent")

		// Step 4: Delete artifact with depth 1
		var scannerArtifact models.Artifact
		f.DB.Where("artifact_name = ? AND asset_id = ?", "scanner", asset.ID).First(&scannerArtifact)

		app := echo.New()
		req := httptest.NewRequest("DELETE", "/vulndb/artifacts/scanner", nil)
		rec := httptest.NewRecorder()
		ctx := app.NewContext(req, rec)

		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("test-user").Maybe()
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, authSession)
		shared.SetArtifact(ctx, scannerArtifact)
		shared.SetAssetVersion(ctx, assetVersion)

		err = f.App.ArtifactController.DeleteArtifact(ctx)
		assert.NoError(t, err)

		// Step 5: Verify depth recalculated to 2 from remaining artifact
		f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2024-DEPTH-TEST", asset.ID).First(&vuln)
		assert.Equal(t, 2, *vuln.ComponentDepth, "Depth should recalculate to 2 after deletion")
		// Note: Risk is not automatically recalculated when depth changes from artifact deletion.
		// The depth assertion above verifies the core functionality.
	})
}
