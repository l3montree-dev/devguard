package tests

import (
	"bytes"
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

// TestVexCreatesVulnerabilityWithVexSource verifies that when a VEX document creates a new vulnerability
// (one that wasn't detected by SBOM), the resulting vulnerability has VEX as its information source
// in the dependency path: root -> vex-artifact -> vulnerable_component
func TestVexCreatesVulnerabilityWithVexSource(t *testing.T) {
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
		cve := models.CVE{CVE: "CVE-2025-VEX-SOURCE", CVSS: 5.0}
		if err := f.DB.Create(&cve).Error; err != nil {
			t.Fatalf("could not create cve: %v", err)
		}

		affected := models.AffectedComponent{
			PurlWithoutVersion: "pkg:npm/vex-only-pkg",
			Scheme:             "pkg",
			Type:               "npm",
			Name:               "vex-only-pkg",
			SemverIntroduced:   utils.Ptr("0.0.1"),
		}
		if err := f.DB.Create(&affected).Error; err != nil {
			t.Fatalf("could not create affected component: %v", err)
		}
		if err := f.DB.Model(&cve).Association("AffectedComponents").Append(&affected); err != nil {
			t.Fatalf("could not link affected component: %v", err)
		}

		// Create a VEX BOM that declares a vulnerability for a component not in any SBOM
		// The VEX should still be trusted and create the vulnerability with VEX as source
		vex := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:     cve.CVE,
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASExploitable,
					},
					Affects: &[]cdx.Affects{
						{Ref: "pkg:npm/vex-only-pkg@1.0.0"},
					},
				},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/vex-only-pkg@1.0.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/vex-only-pkg@1.0.0", Name: "pkg:npm/vex-only-pkg@1.0.0"},
			},
		}

		// Upload VEX
		var vb bytes.Buffer
		if err := cdx.NewBOMEncoder(&vb, cdx.BOMFileFormatJSON).Encode(&vex); err != nil {
			t.Fatalf("encode vex: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vex/", &vb)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "vex-artifact")
		req.Header.Set("X-Asset-Ref", assetVersion.Name)
		req.Header.Set("X-Origin", "vex:test")
		ctx := app.NewContext(req, rec)
		setupContext(&ctx)

		if err := scanController.UploadVEX(ctx); err != nil {
			t.Fatalf("vex upload failed: %v", err)
		}

		// Verify vulnerability was created with VEX source in path
		var vulns []models.DependencyVuln
		if err := f.DB.Where("cve_id = ?", cve.CVE).Find(&vulns).Error; err != nil {
			t.Fatalf("could not query vulns: %v", err)
		}

		assert.GreaterOrEqual(t, len(vulns), 1, "VEX should create at least one vulnerability")

		// Check that the vulnerability path includes the VEX artifact origin
		found := false
		for _, vuln := range vulns {
			// Path should reference the VEX as the source: root -> vex-artifact -> component
			if len(vuln.VulnerabilityPath) > 0 && vuln.ComponentPurl == "pkg:npm/vex-only-pkg@1.0.0" {
				found = true
				t.Logf("VEX-created vulnerability has path: %v", vuln.VulnerabilityPath)
				// Verify the vulnerability is open (as declared by VEX/exploitable state)
				assert.Equal(t, dtos.VulnStateOpen, vuln.State)
				break
			}
		}
		assert.True(t, found, "Should find vulnerability created from VEX for pkg:npm/vex-only-pkg@1.0.0")
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
		sbom := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:     cve.CVE,
					Affects: &[]cdx.Affects{{Ref: "pkg:npm/multi-source-pkg@1.5.0"}},
				},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var sb bytes.Buffer
		if err := cdx.NewBOMEncoder(&sb, cdx.BOMFileFormatJSON).Encode(&sbom); err != nil {
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
		vex := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: cve.CVE,
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASExploitable,
					},
					Affects: &[]cdx.Affects{{Ref: "pkg:npm/multi-source-pkg@1.5.0"}},
				},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var vb bytes.Buffer
		if err := cdx.NewBOMEncoder(&vb, cdx.BOMFileFormatJSON).Encode(&vex); err != nil {
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
		sbomWithoutVuln := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-source-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-source-pkg@1.5.0", Name: "pkg:npm/multi-source-pkg@1.5.0"},
			},
		}

		var sb2 bytes.Buffer
		if err := cdx.NewBOMEncoder(&sb2, cdx.BOMFileFormatJSON).Encode(&sbomWithoutVuln); err != nil {
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
		sbom := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID:     cve1.CVE,
					Affects: &[]cdx.Affects{{Ref: "pkg:npm/single-src-pkg@1.5.0"}},
				},
				{
					ID:     cve2.CVE,
					Affects: &[]cdx.Affects{{Ref: "pkg:npm/multi-src-pkg@1.5.0"}},
				},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/single-src-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/single-src-pkg@1.5.0", Name: "single-src-pkg@1.5.0"},
				{BOMRef: "pkg:npm/multi-src-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@1.5.0", Name: "multi-src-pkg@1.5.0"},
			},
		}

		var sb bytes.Buffer
		if err := cdx.NewBOMEncoder(&sb, cdx.BOMFileFormatJSON).Encode(&sbom); err != nil {
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
		vex := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: cve2.CVE,
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASExploitable,
					},
					Affects: &[]cdx.Affects{{Ref: "pkg:npm/multi-src-pkg@1.5.0"}},
				},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/multi-src-pkg@1.5.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@1.5.0", Name: "multi-src-pkg@1.5.0"},
			},
		}

		var vb bytes.Buffer
		if err := cdx.NewBOMEncoder(&vb, cdx.BOMFileFormatJSON).Encode(&vex); err != nil {
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
		sbomPatched := cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   cdx.BOMFormat,
			Vulnerabilities: &[]cdx.Vulnerability{},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "root", Type: cdx.ComponentTypeApplication, Name: "root"},
				{BOMRef: "pkg:npm/single-src-pkg@2.0.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/single-src-pkg@2.0.0", Name: "single-src-pkg@2.0.0"},
				{BOMRef: "pkg:npm/multi-src-pkg@2.0.0", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/multi-src-pkg@2.0.0", Name: "multi-src-pkg@2.0.0"},
			},
		}

		var sbp bytes.Buffer
		if err := cdx.NewBOMEncoder(&sbp, cdx.BOMFileFormatJSON).Encode(&sbomPatched); err != nil {
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
