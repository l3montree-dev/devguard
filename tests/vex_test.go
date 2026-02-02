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

	"github.com/CycloneDX/cyclonedx-go"
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

// createVexPriorityCVEs creates all CVEs referenced in the vex-priority.json file
// VEX rules are created for all vulnerabilities in the file, so all CVE IDs must exist
func createVexPriorityCVEs(db shared.DB) {
	cves := []models.CVE{
		{CVE: "GO-2025-4134", Description: "golang.org/x/crypto vulnerability"},
		{CVE: "GO-2025-4135", Description: "golang.org/x/crypto vulnerability"},
		{CVE: "GHSA-w73w-5m7g-f7qc", Description: "jwt-go vulnerability"},
		{CVE: "GO-2020-0017", Description: "jwt-go vulnerability"},
		{CVE: "GHSA-3xh2-74w9-5vxm", Description: "gorilla/websocket vulnerability"},
		{CVE: "GO-2020-0019", Description: "gorilla/websocket vulnerability"},
		{CVE: "GHSA-f6x5-jh6r-wrfv", Description: "golang.org/x/crypto vulnerability"},
	}

	for _, cve := range cves {
		if err := db.Create(&cve).Error; err != nil {
			panic(err)
		}
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

		// Create the CVEs that the VEX file references
		createCVEGHSA_j5w8_q4qc_rx2x(f.DB)
		createVexPriorityCVEs(f.DB)

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

		// Create the CVEs that the VEX file references
		createCVEGHSA_j5w8_q4qc_rx2x(f.DB)
		createVexPriorityCVEs(f.DB)

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

// TestMultiSourceVulnerabilityNotClosedWhenOneSourceRemoves verifies that a vulnerability
// detected from both SBOM and VEX cannot be closed by one source removing it.
// Only vulnerabilities with a single source can be closed.
func TestMultiSourceVulnerabilityNotClosedWhenOneSourceRemoves(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()
		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx *shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("tester")
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)
			shared.SetSession(*ctx, authSession)
		}

		// Create CVE and affected component
		cve := models.CVE{CVE: "CVE-2025-MULTI-SOURCE", CVSS: 5.0}
		if err := f.DB.Create(&cve).Error; err != nil {
			t.Fatalf("could not create cve: %v", err)
		}

		affected := models.AffectedComponent{
			PurlWithoutVersion: "pkg:npm/multi-source-pkg",
			Scheme:             "pkg",
			Type:               "npm",
			Name:               "multi-source-pkg",
			SemverIntroduced:   utils.Ptr("1.0.0"),
		}
		if err := f.DB.Create(&affected).Error; err != nil {
			t.Fatalf("could not create affected component: %v", err)
		}
		if err := f.DB.Model(&cve).Association("AffectedComponents").Append(&affected); err != nil {
			t.Fatalf("could not link affected component: %v", err)
		}

		// Step 1: Upload SBOM that detects the vulnerability
		sbom := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			BOMFormat:   cyclonedx.BOMFormat,
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					ID:      cve.CVE,
					Affects: &[]cyclonedx.Affects{{Ref: "pkg:npm/multi-source-pkg@1.5.0"}},
				},
			},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var sb bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&sb, cyclonedx.BOMFileFormatJSON).Encode(&sbom); err != nil {
			t.Fatalf("encode sbom: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &sb)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "sbom-artifact")
		req.Header.Set("X-Asset-Default-Branch", "main")
		ctx := app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.ScanDependencyVulnFromProject(ctx); err != nil {
			t.Fatalf("sbom scan failed: %v", err)
		}

		// Verify vulnerability opened from SBOM
		var vulnsSBOM []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve.CVE).Find(&vulnsSBOM).Error; err != nil {
			t.Fatalf("could not query vulns after sbom: %v", err)
		}
		assert.GreaterOrEqual(t, len(vulnsSBOM), 1, "SBOM should detect the vulnerability")
		assert.Equal(t, dtos.VulnStateOpen, vulnsSBOM[0].State)

		// Step 2: Upload VEX that also references the same vulnerability (multi-source now)
		vex := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			BOMFormat:   cyclonedx.BOMFormat,
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					ID: cve.CVE,
					Analysis: &cyclonedx.VulnerabilityAnalysis{
						State: cyclonedx.IASExploitable,
					},
					Affects: &[]cyclonedx.Affects{{Ref: "pkg:npm/multi-source-pkg@1.5.0"}},
				},
			},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var vb bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&vb, cyclonedx.BOMFileFormatJSON).Encode(&vex); err != nil {
			t.Fatalf("encode vex: %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/vex/", &vb)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "vex-artifact")
		req.Header.Set("X-Asset-Ref", assetVersion.Name)
		req.Header.Set("X-Origin", "vex:test")
		ctx = app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.UploadVEX(ctx); err != nil {
			t.Fatalf("vex upload failed: %v", err)
		}

		// Vulnerability should still be open (multi-source)
		var vulnsAfterVex []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve.CVE).Find(&vulnsAfterVex).Error; err != nil {
			t.Fatalf("could not query vulns after vex: %v", err)
		}

		// Verify vulnerability remains open because it has multiple sources
		assert.GreaterOrEqual(t, len(vulnsAfterVex), 1)
		assert.Equal(t, dtos.VulnStateOpen, vulnsAfterVex[0].State,
			"Multi-source vulnerability should remain open even when both sources agree it's exploitable")

		// Step 3: Remove SBOM scan (upload new SBOM without the vulnerability)
		sbomWithoutVuln := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			BOMFormat:   cyclonedx.BOMFormat,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var sb2 bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&sb2, cyclonedx.BOMFileFormatJSON).Encode(&sbomWithoutVuln); err != nil {
			t.Fatalf("encode sbom2: %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &sb2)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "sbom-artifact")
		req.Header.Set("X-Asset-Default-Branch", "main")
		ctx = app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.ScanDependencyVulnFromProject(ctx); err != nil {
			t.Fatalf("sbom scan 2 failed: %v", err)
		}

		// Vulnerability should still be open because VEX still references it (multi-source)
		var vulnsAfterSbom2 []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve.CVE).Find(&vulnsAfterSbom2).Error; err != nil {
			t.Fatalf("could not query vulns after sbom2: %v", err)
		}

		assert.GreaterOrEqual(t, len(vulnsAfterSbom2), 1,
			"Vulnerability should not be removed when one source (SBOM) stops detecting it if another source (VEX) still references it")
		assert.Equal(t, dtos.VulnStateOpen, vulnsAfterSbom2[0].State,
			"Multi-source vulnerability should remain open even when SBOM source is removed")
	})
}

// TestOnlySingleSourceVulnerabilityCanBeFixedByScans verifies that only vulnerabilities
// with a single source (either SBOM or VEX, but not both) can be automatically closed/fixed by scan updates.
// Multi-source vulnerabilities require explicit user action to be closed.
func TestOnlySingleSourceVulnerabilityCanBeFixedByScans(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()
		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx *shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("tester")
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)
			shared.SetSession(*ctx, authSession)
		}

		// Create TWO CVEs: one for single-source, one for multi-source
		cve1 := models.CVE{CVE: "CVE-2025-SINGLE-SOURCE", CVSS: 5.0}
		if err := f.DB.Create(&cve1).Error; err != nil {
			t.Fatalf("could not create cve1: %v", err)
		}

		cve2 := models.CVE{CVE: "CVE-2025-MULTI-FIXED", CVSS: 5.0}
		if err := f.DB.Create(&cve2).Error; err != nil {
			t.Fatalf("could not create cve2: %v", err)
		}

		// Create affected components
		for _, cveName := range []string{"single-src-pkg", "multi-src-pkg"} {
			affected := models.AffectedComponent{
				PurlWithoutVersion: "pkg:npm/" + cveName,
				Scheme:             "pkg",
				Type:               "npm",
				Name:               cveName,
				SemverFixed:        utils.Ptr("2.0.0"),
			}
			if err := f.DB.Create(&affected).Error; err != nil {
				t.Fatalf("could not create affected component for %s: %v", cveName, err)
			}

			cveToLink := cve1
			if cveName == "multi-src-pkg" {
				cveToLink = cve2
			}
			if err := f.DB.Model(&cveToLink).Association("AffectedComponents").Append(&affected); err != nil {
				t.Fatalf("could not link affected component: %v", err)
			}
		}

		// SINGLE SOURCE scenario: Only SBOM detects the vulnerability
		sbom := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			BOMFormat:   cyclonedx.BOMFormat,
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					ID:      cve1.CVE,
					Affects: &[]cyclonedx.Affects{{Ref: "pkg:npm/single-src-pkg@1.5.0"}},
				},
				{
					ID:      cve2.CVE,
					Affects: &[]cyclonedx.Affects{{Ref: "pkg:npm/multi-src-pkg@1.5.0"}},
				},
			},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/single-src-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/single-src-pkg@1.5.0", Name: "single-src-pkg@1.5.0"},
				{BOMRef: "pkg:npm/multi-src-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@1.5.0", Name: "multi-src-pkg@1.5.0"},
			},
		}

		var sb bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&sb, cyclonedx.BOMFileFormatJSON).Encode(&sbom); err != nil {
			t.Fatalf("encode sbom: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &sb)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "sbom-artifact")
		req.Header.Set("X-Asset-Default-Branch", "main")
		ctx := app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.ScanDependencyVulnFromProject(ctx); err != nil {
			t.Fatalf("sbom scan failed: %v", err)
		}

		// Add VEX source to CVE2 (making it multi-source)
		vex := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			BOMFormat:   cyclonedx.BOMFormat,
			Vulnerabilities: &[]cyclonedx.Vulnerability{
				{
					ID: cve2.CVE,
					Analysis: &cyclonedx.VulnerabilityAnalysis{
						State: cyclonedx.IASExploitable,
					},
					Affects: &[]cyclonedx.Affects{{Ref: "pkg:npm/multi-src-pkg@1.5.0"}},
				},
			},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-src-pkg@1.5.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@1.5.0", Name: "multi-src-pkg@1.5.0"},
			},
		}

		var vb bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&vb, cyclonedx.BOMFileFormatJSON).Encode(&vex); err != nil {
			t.Fatalf("encode vex: %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/vex/", &vb)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "vex-artifact")
		req.Header.Set("X-Asset-Ref", assetVersion.Name)
		req.Header.Set("X-Origin", "vex:test")
		ctx = app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.UploadVEX(ctx); err != nil {
			t.Fatalf("vex upload failed: %v", err)
		}

		// Now upload a patched SBOM (version 2.0.0) that fixes both vulnerabilities
		sbomPatched := cyclonedx.BOM{
			SpecVersion:     cyclonedx.SpecVersion1_6,
			BOMFormat:       cyclonedx.BOMFormat,
			Vulnerabilities: &[]cyclonedx.Vulnerability{},
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cyclonedx.Component{
				{BOMRef: "root", Type: cyclonedx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/single-src-pkg@2.0.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/single-src-pkg@2.0.0", Name: "single-src-pkg@2.0.0"},
				{BOMRef: "pkg:npm/multi-src-pkg@2.0.0", Type: cyclonedx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@2.0.0", Name: "multi-src-pkg@2.0.0"},
			},
		}

		var sbp bytes.Buffer
		if err := cyclonedx.NewBOMEncoder(&sbp, cyclonedx.BOMFileFormatJSON).Encode(&sbomPatched); err != nil {
			t.Fatalf("encode patched sbom: %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &sbp)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "sbom-artifact")
		req.Header.Set("X-Asset-Default-Branch", "main")
		ctx = app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.ScanDependencyVulnFromProject(ctx); err != nil {
			t.Fatalf("patched sbom scan failed: %v", err)
		}

		// Check results
		var singleSrcVulns []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve1.CVE).Find(&singleSrcVulns).Error; err != nil {
			t.Fatalf("could not query single-src vulns: %v", err)
		}

		var multiSrcVulns []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve2.CVE).Find(&multiSrcVulns).Error; err != nil {
			t.Fatalf("could not query multi-src vulns: %v", err)
		}

		// Single-source vulnerability SHOULD be fixed (only SBOM detected it, and patched version removes it)
		if len(singleSrcVulns) > 0 {
			assert.Equal(t, dtos.VulnStateFixed, singleSrcVulns[0].State,
				"Single-source vulnerability should be fixed when SBOM version is updated to patched version")
		}

		// Multi-source vulnerability should NOT be fixed (even though SBOM source is fixed, VEX still references it as exploitable)
		assert.GreaterOrEqual(t, len(multiSrcVulns), 1,
			"Multi-source vulnerability record should still exist")
		assert.NotEqual(t, dtos.VulnStateFixed, multiSrcVulns[0].State,
			"Multi-source vulnerability should NOT be fixed by SBOM scan when VEX still declares it exploitable")
	})
}
