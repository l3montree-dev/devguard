// Copyright (C) 2025 l3montree GmbH
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

package tests

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// createCVEGHSA_j5w8_q4qc_rx2x creates the GHSA-j5w8-q4qc-rx2x CVE that affects golang.org/x/crypto
func createCVEGHSA_j5w8_q4qc_rx2x(db shared.DB) {
	cve := models.CVE{
		CVE:         "GHSA-j5w8-q4qc-rx2x",
		Description: "golang.org/x/crypto vulnerability",
		CVSS:        5.3,
		Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
	}

	err := db.Create(&cve).Error
	if err != nil {
		panic(err)
	}

	affectedComponent := models.AffectedComponent{
		PurlWithoutVersion: "pkg:golang/golang.org/x/crypto",
		Scheme:             "pkg",
		Type:               "golang",
		Name:               "golang.org/x/crypto",
		Namespace:          utils.Ptr(""),
		Qualifiers:         nil,
		SemverFixed:        utils.Ptr("0.44.0"), // Fixed in 0.44.0, so 0.43.0 is vulnerable
	}

	err = db.Create(&affectedComponent).Error
	if err != nil {
		panic(err)
	}

	// create the relationship between the CVE and the affected component
	err = db.Model(&cve).Association("AffectedComponents").Append(&affectedComponent)
	if err != nil {
		panic(err)
	}
}

func getVexPrioritySBOMContent() []byte {
	file, err := os.Open("./testdata/vex-priority-sbom.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return content
}

func getVexPriorityContent() []byte {
	file, err := os.Open("./testdata/vex-priority.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return content
}

// TestVexPriorityMultiplePaths tests that VEX state is applied to ALL vulnerabilities
// with the same CVE+PURL combination, regardless of their vulnerability path.
// DevGuard creates multiple DependencyVuln records for the same CVE - one per unique path.
// VEX references just CVE + PURL (no path info), so it should apply to ALL matching vulns.
// This reproduces the bug described in GitHub issue #1616.
func TestVexPriorityMultiplePaths(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ParanoidMode = false
		if err := f.DB.Save(&asset).Error; err != nil {
			t.Fatalf("could not save asset: %v", err)
		}

		// Create the CVE that the VEX file references
		createCVEGHSA_j5w8_q4qc_rx2x(f.DB)

		setupContext := func(ctx *shared.Context) {
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetSession(*ctx, authSession)
		}

		t.Run("VEX should apply to ALL vulnerabilities with same CVE+PURL regardless of path", func(t *testing.T) {
			artifactName := "vex-priority-test"

			// Step 1: Upload the SBOM - this creates vulnerabilities (possibly with multiple paths)
			recorder := httptest.NewRecorder()
			sbomContent := getVexPrioritySBOMContent()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(sbomContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)

			err := scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get all vulnerabilities for GHSA-j5w8-q4qc-rx2x (there may be multiple paths)
			var initialVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&initialVulns).Error
			assert.Nil(t, err)
			t.Logf("After SBOM upload - Found %d vulnerabilities for GHSA-j5w8-q4qc-rx2x", len(initialVulns))

			for i, v := range initialVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v", i, v.State, v.VulnerabilityPath)
			}

			// Step 2: Upload VEX - this should mark the vulnerability as fixed
			recorder = httptest.NewRecorder()
			vexContent := getVexPriorityContent()
			req = httptest.NewRequest("POST", "/vex/", bytes.NewReader(vexContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.UploadVEX(ctx)
			assert.Nil(t, err, "VEX upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get all vulnerabilities after VEX - ALL should be fixed
			var afterVexVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&afterVexVulns).Error
			assert.Nil(t, err)
			t.Logf("After VEX upload - Found %d vulnerabilities", len(afterVexVulns))

			// ALL vulnerabilities should now be fixed (or the VEX state)
			for i, v := range afterVexVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
				// The VEX should have applied to ALL paths
				assert.NotEqual(t, dtos.VulnStateOpen, v.State,
					"After VEX upload, vulnerability at path %v should NOT be open", v.VulnerabilityPath)
			}

			// Step 3: Upload SBOM again - states should NOT revert to open
			recorder = httptest.NewRecorder()
			sbomContent = getVexPrioritySBOMContent()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(sbomContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "Second SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get final state of all vulnerabilities
			var finalVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&finalVulns).Error
			assert.Nil(t, err)
			t.Logf("After second SBOM upload - Found %d vulnerabilities", len(finalVulns))

			// ALL vulnerabilities should STILL be in the VEX state (not reverted to open)
			openCount := 0
			for i, v := range finalVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
				if v.State == dtos.VulnStateOpen {
					openCount++
				}
			}

			// The critical assertion: NO vulnerabilities should have reverted to open
			assert.Equal(t, 0, openCount,
				"After second SBOM upload, %d/%d vulnerabilities reverted to open - VEX state should persist for ALL paths",
				openCount, len(finalVulns))
		})
	})
}

// TestVexFalsePositiveWithDependencyPath tests that VEX false positive applies correctly
// when the SBOM has a dependency path (a -> b -> vulnerable_c) but the VEX only references
// the vulnerable component (c) without path information.
// This tests the scenario: SBOM upload, VEX upload (false positive), SBOM upload again.
func TestVexFalsePositiveWithDependencyPath(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ParanoidMode = false
		if err := f.DB.Save(&asset).Error; err != nil {
			t.Fatalf("could not save asset: %v", err)
		}

		// Create a CVE for testing - CVE-2099-0001 affects pkg:golang/vulnerable-lib
		cve := models.CVE{
			CVE:         "CVE-2099-0001",
			Description: "Test vulnerability in vulnerable-lib",
			CVSS:        7.5,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		}
		if err := f.DB.Create(&cve).Error; err != nil {
			t.Fatalf("could not create CVE: %v", err)
		}

		affectedComponent := models.AffectedComponent{
			PurlWithoutVersion: "pkg:golang/github.com/example/vulnerable-lib",
			Scheme:             "pkg",
			Type:               "golang",
			Name:               "github.com/example/vulnerable-lib",
			Namespace:          utils.Ptr(""),
			SemverFixed:        utils.Ptr("2.0.0"), // Fixed in 2.0.0, so 1.0.0 is vulnerable
		}
		if err := f.DB.Create(&affectedComponent).Error; err != nil {
			t.Fatalf("could not create affected component: %v", err)
		}
		if err := f.DB.Model(&cve).Association("AffectedComponents").Append(&affectedComponent); err != nil {
			t.Fatalf("could not link CVE to affected component: %v", err)
		}

		setupContext := func(ctx *shared.Context) {
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetSession(*ctx, authSession)
		}

		// SBOM with dependency path: app -> intermediate-lib -> vulnerable-lib
		// Path: a -> b -> c (where c is the vulnerable component)
		sbomWithPath := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"version": 1,
			"metadata": {
				"component": {
					"bom-ref": "pkg:golang/github.com/example/my-app@1.0.0",
					"type": "application",
					"name": "my-app",
					"version": "1.0.0",
					"purl": "pkg:golang/github.com/example/my-app@1.0.0"
				}
			},
			"components": [
				{
					"bom-ref": "pkg:golang/github.com/example/my-app@1.0.0",
					"type": "application",
					"name": "my-app",
					"version": "1.0.0",
					"purl": "pkg:golang/github.com/example/my-app@1.0.0"
				},
				{
					"bom-ref": "pkg:golang/github.com/example/intermediate-lib@1.0.0",
					"type": "library",
					"name": "intermediate-lib",
					"version": "1.0.0",
					"purl": "pkg:golang/github.com/example/intermediate-lib@1.0.0"
				},
				{
					"bom-ref": "pkg:golang/github.com/example/vulnerable-lib@1.0.0",
					"type": "library",
					"name": "vulnerable-lib",
					"version": "1.0.0",
					"purl": "pkg:golang/github.com/example/vulnerable-lib@1.0.0"
				}
			],
			"dependencies": [
				{
					"ref": "pkg:golang/github.com/example/my-app@1.0.0",
					"dependsOn": ["pkg:golang/github.com/example/intermediate-lib@1.0.0"]
				},
				{
					"ref": "pkg:golang/github.com/example/intermediate-lib@1.0.0",
					"dependsOn": ["pkg:golang/github.com/example/vulnerable-lib@1.0.0"]
				},
				{
					"ref": "pkg:golang/github.com/example/vulnerable-lib@1.0.0",
					"dependsOn": []
				}
			]
		}`

		// VEX marking the vulnerability as false positive - only references the component, not the path
		vexFalsePositive := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"version": 1,
			"metadata": {
				"component": {
					"bom-ref": "pkg:golang/github.com/example/my-app@1.0.0",
					"type": "application",
					"name": "my-app"
				}
			},
			"vulnerabilities": [
				{
					"id": "CVE-2099-0001",
					"source": {
						"name": "NVD",
						"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"
					},
					"analysis": {
						"state": "false_positive",
						"detail": "We analyzed this and determined it does not affect our usage"
					},
					"affects": [
						{
							"ref": "pkg:golang/github.com/example/vulnerable-lib@1.0.0"
						}
					]
				}
			]
		}`

		t.Run("VEX false positive should apply to vulnerability with dependency path and persist after SBOM re-upload", func(t *testing.T) {
			artifactName := "path-test-artifact"

			// Step 1: Upload SBOM with dependency path (a -> b -> c)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader([]byte(sbomWithPath)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)

			err := scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "First SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get the vulnerability after first SBOM upload
			var initialVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"CVE-2099-0001", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&initialVulns).Error
			assert.Nil(t, err)
			assert.GreaterOrEqual(t, len(initialVulns), 1, "Should find at least one vulnerability")

			t.Logf("After first SBOM upload - Found %d vulnerabilities", len(initialVulns))
			for i, v := range initialVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
				assert.Equal(t, dtos.VulnStateOpen, v.State, "Initial state should be open")
			}

			// Step 2: Upload VEX marking as false positive
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/vex/", bytes.NewReader([]byte(vexFalsePositive)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.UploadVEX(ctx)
			assert.Nil(t, err, "VEX upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get vulnerabilities after VEX upload - ALL should be false positive
			var afterVexVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"CVE-2099-0001", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&afterVexVulns).Error
			assert.Nil(t, err)

			t.Logf("After VEX upload - Found %d vulnerabilities", len(afterVexVulns))
			for i, v := range afterVexVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
				assert.Equal(t, dtos.VulnStateFalsePositive, v.State,
					"After VEX upload, vulnerability at path %v should be false_positive", v.VulnerabilityPath)
			}

			// Step 3: Upload SBOM again - states should NOT revert to open
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader([]byte(sbomWithPath)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "Second SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get final state - should still be false_positive
			var finalVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"CVE-2099-0001", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&finalVulns).Error
			assert.Nil(t, err)

			t.Logf("After second SBOM upload - Found %d vulnerabilities", len(finalVulns))
			openCount := 0
			for i, v := range finalVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
				if v.State == dtos.VulnStateOpen {
					openCount++
				}
				// Log events for debugging
				for j, ev := range v.Events {
					t.Logf("    Event %d: Type=%v, Upstream=%v", j, ev.Type, ev.Upstream)
				}
			}

			// Critical assertion: NO vulnerabilities should have reverted to open
			assert.Equal(t, 0, openCount,
				"After second SBOM upload, %d/%d vulnerabilities reverted to open - VEX false_positive should persist for ALL paths",
				openCount, len(finalVulns))

			// All should still be false_positive
			for _, v := range finalVulns {
				assert.Equal(t, dtos.VulnStateFalsePositive, v.State,
					"Vulnerability at path %v should remain false_positive after SBOM re-upload", v.VulnerabilityPath)
			}
		})
	})
}

// TestVexPriorityAlternatingState tests that vulnerability state does not alternate
// when uploading VEX and SBOM files in sequence.
// This reproduces the bug described in GitHub issue #1616.
func TestVexPriorityAlternatingState(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ParanoidMode = false
		if err := f.DB.Save(&asset).Error; err != nil {
			t.Fatalf("could not save asset: %v", err)
		}

		// Create the CVE that the VEX file references
		createCVEGHSA_j5w8_q4qc_rx2x(f.DB)

		setupContext := func(ctx *shared.Context) {
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetSession(*ctx, authSession)
		}

		t.Run("vulnerability state should not alternate between Fixed and Detected on repeated VEX/SBOM uploads", func(t *testing.T) {
			artifactName := "vex-priority-test"

			// Step 1: Upload the SBOM first - this should detect the vulnerability
			recorder := httptest.NewRecorder()
			sbomContent := getVexPrioritySBOMContent()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(sbomContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)

			err := scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "First SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get ALL vulnerabilities for GHSA-j5w8-q4qc-rx2x (there may be multiple with different paths)
			var initialVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&initialVulns).Error
			assert.Nil(t, err, "Should find the vulnerability after first SBOM upload")
			assert.GreaterOrEqual(t, len(initialVulns), 1, "Should have at least one vulnerability")
			t.Logf("After first SBOM upload - Found %d vulnerabilities for GHSA-j5w8-q4qc-rx2x", len(initialVulns))
			for i, v := range initialVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
			}
			initialVuln := initialVulns[0]
			_ = initialVuln // will be used for reference

			// Step 2: Upload the VEX - this should apply the VEX state
			recorder = httptest.NewRecorder()
			vexContent := getVexPriorityContent()
			req = httptest.NewRequest("POST", "/vex/", bytes.NewReader(vexContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.UploadVEX(ctx)
			assert.Nil(t, err, "VEX upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get ALL vulnerabilities after VEX upload - check if new ones were created
			var afterVexVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				Find(&afterVexVulns).Error
			assert.Nil(t, err, "Should find vulnerabilities after VEX upload")
			t.Logf("After VEX upload - Found %d vulnerabilities for GHSA-j5w8-q4qc-rx2x", len(afterVexVulns))
			for i, v := range afterVexVulns {
				t.Logf("  Vuln %d: State=%s, Path=%v, Events=%d", i, v.State, v.VulnerabilityPath, len(v.Events))
			}
			// For backward compatibility, use the first one
			stateAfterVex := afterVexVulns[0].State

			// Step 3: Upload the SBOM again - the state should NOT change back
			recorder = httptest.NewRecorder()
			sbomContent = getVexPrioritySBOMContent()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(sbomContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "Second SBOM upload should succeed")
			assert.Equal(t, 200, recorder.Code)

			// Get the state after second SBOM upload
			var afterSecondSbomVuln models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				First(&afterSecondSbomVuln).Error
			assert.Nil(t, err, "Should find the vulnerability after second SBOM upload")
			stateAfterSecondSbom := afterSecondSbomVuln.State
			t.Logf("After second SBOM upload - State: %s, Events count: %d", stateAfterSecondSbom, len(afterSecondSbomVuln.Events))

			// The critical assertion: state after second SBOM should equal state after VEX
			// It should NOT have alternated back to the initial state
			assert.Equal(t, stateAfterVex, stateAfterSecondSbom,
				"State should NOT alternate - should remain at VEX state after second SBOM upload")

			// Additional check: if VEX set it to accepted/fixed/falsePositive, it should stay that way
			if stateAfterVex == dtos.VulnStateAccepted || stateAfterVex == dtos.VulnStateFixed || stateAfterVex == dtos.VulnStateFalsePositive {
				assert.NotEqual(t, dtos.VulnStateOpen, stateAfterSecondSbom,
					"Vulnerability should not reopen after being marked as %s by VEX", stateAfterVex)
			}

			// Step 4: Upload VEX again and then SBOM - verify state remains stable
			recorder = httptest.NewRecorder()
			vexContent = getVexPriorityContent()
			req = httptest.NewRequest("POST", "/vex/", bytes.NewReader(vexContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.UploadVEX(ctx)
			assert.Nil(t, err, "Second VEX upload should succeed")

			// Get state after second VEX
			var afterSecondVexVuln models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				First(&afterSecondVexVuln).Error
			assert.Nil(t, err)
			stateAfterSecondVex := afterSecondVexVuln.State
			t.Logf("After second VEX upload - State: %s, Events count: %d", stateAfterSecondVex, len(afterSecondVexVuln.Events))

			// Upload SBOM again
			recorder = httptest.NewRecorder()
			sbomContent = getVexPrioritySBOMContent()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(sbomContent))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err, "Third SBOM upload should succeed")

			// Get final state
			var finalVuln models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_version_name = ? AND asset_id = ?",
				"GHSA-j5w8-q4qc-rx2x", assetVersion.Name, asset.ID).
				Preload("Events").
				First(&finalVuln).Error
			assert.Nil(t, err)
			finalState := finalVuln.State
			t.Logf("Final state - State: %s, Events count: %d", finalState, len(finalVuln.Events))

			// Final state should equal the state after VEX
			assert.Equal(t, stateAfterSecondVex, finalState,
				"State should remain stable after VEX upload, not alternate on SBOM uploads")

			// Log all events for debugging
			t.Log("Event history:")
			for i, event := range finalVuln.Events {
				t.Logf("  %d: Type=%v, Upstream=%v, CreatedAt=%v",
					i, event.Type, event.Upstream, event.CreatedAt)
			}
		})
	})
}

// TestVexTrustsNonExistingVulnerabilities verifies that when a VEX declares a vulnerability
// that doesn't exist yet in the system, we "trust" the VEX and do NOT create a new vulnerability.
// The VEX statement should be silently skipped without creating any new DependencyVuln records.
func TestVexTrustsNonExistingVulnerabilities(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ParanoidMode = false
		if err := f.DB.Save(&asset).Error; err != nil {
			t.Fatalf("could not save asset: %v", err)
		}

		// Create a CVE that the VEX references - but we WON'T upload an SBOM that contains it
		cve := models.CVE{
			CVE:         "CVE-2099-9999",
			Description: "A vulnerability that exists in CVE DB but not in our SBOM",
			CVSS:        8.0,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		}
		if err := f.DB.Create(&cve).Error; err != nil {
			t.Fatalf("could not create CVE: %v", err)
		}

		affectedComponent := models.AffectedComponent{
			PurlWithoutVersion: "pkg:golang/github.com/example/not-in-our-sbom",
			Scheme:             "pkg",
			Type:               "golang",
			Name:               "github.com/example/not-in-our-sbom",
			SemverFixed:        utils.Ptr("2.0.0"),
		}
		if err := f.DB.Create(&affectedComponent).Error; err != nil {
			t.Fatalf("could not create affected component: %v", err)
		}
		if err := f.DB.Model(&cve).Association("AffectedComponents").Append(&affectedComponent); err != nil {
			t.Fatalf("could not link CVE to affected component: %v", err)
		}

		setupContext := func(ctx *shared.Context) {
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetSession(*ctx, authSession)
		}

		// VEX that references a vulnerability that doesn't exist in any SBOM
		vexForNonExisting := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.6",
			"version": 1,
			"metadata": {
				"component": {
					"bom-ref": "pkg:golang/github.com/example/my-app@1.0.0",
					"type": "application",
					"name": "my-app"
				}
			},
			"vulnerabilities": [
				{
					"id": "CVE-2099-9999",
					"source": {
						"name": "NVD",
						"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-9999"
					},
					"analysis": {
						"state": "false_positive",
						"detail": "This component is not used in our application"
					},
					"affects": [
						{
							"ref": "pkg:golang/github.com/example/not-in-our-sbom@1.0.0"
						}
					]
				}
			]
		}`

		t.Run("VEX should NOT create vulnerabilities for non-existing components", func(t *testing.T) {
			artifactName := "trust-vex-test"

			// Verify no vulnerabilities exist for this CVE before VEX upload
			var beforeVulns []models.DependencyVuln
			err := f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2099-9999", asset.ID).Find(&beforeVulns).Error
			assert.Nil(t, err)
			assert.Equal(t, 0, len(beforeVulns), "No vulnerabilities should exist before VEX upload")

			// Upload VEX that references a non-existing vulnerability
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/vex/", bytes.NewReader([]byte(vexForNonExisting)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)

			err = scanController.UploadVEX(ctx)
			assert.Nil(t, err, "VEX upload should succeed even when referencing non-existing vulnerabilities")
			assert.Equal(t, 200, recorder.Code)

			// Verify NO vulnerabilities were created - we trust the VEX and skip non-existing ones
			var afterVulns []models.DependencyVuln
			err = f.DB.Where("cve_id = ? AND asset_id = ?", "CVE-2099-9999", asset.ID).Find(&afterVulns).Error
			assert.Nil(t, err)
			assert.Equal(t, 0, len(afterVulns),
				"VEX should NOT create vulnerabilities for components that don't exist in any SBOM - we trust the VEX")

			t.Logf("VEX upload succeeded without creating vulnerabilities for non-existing components")
		})
	})
}
