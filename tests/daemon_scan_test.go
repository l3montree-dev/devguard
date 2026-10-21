package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

// TestScanAllAssetsDetectsVulns tests that the scan opens a vuln for a vulnerable component
func TestScanAllAssetsDetectsVulns(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-scan-vuln")
		project := f.CreateProject(org.ID, "test-project-scan")
		asset := f.CreateAsset(project.ID, "test-asset-scan")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
		// Create CVE and affected component
		cve := models.CVE{
			CVE:              "CVE-2025-SCAN-001",
			DatePublished:    time.Now().Add(-24 * time.Hour),
			DateLastModified: time.Now().Add(-12 * time.Hour),
			Description:      "Test vulnerability for scan testing",
			CVSS:             9.0,
		}
		err := f.DB.Create(&cve).Error
		assert.NoError(t, err)

		affectedComponent, err := createTestAffectedComponent("pkg:npm/vulnerable-package@2.0.0", []models.CVE{cve})
		assert.NoError(t, err)
		err = f.DB.Create(&affectedComponent).Error
		assert.NoError(t, err)

		// Create component
		component := models.Component{
			ID: "pkg:npm/vulnerable-package@2.0.0",
		}
		err = f.DB.Create(&component).Error
		assert.NoError(t, err)

		// Create artifact
		artifact := models.Artifact{
			ArtifactName:     "scan-test-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		err = SeedDirectDependencies(f.DB, assetVersion, artifact.ArtifactName, "pkg:npm/vulnerable-package@2.0.0")
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.ScanAllAssets(context.Background())
		assert.NoError(t, err)

		// Verify vulnerability was detected
		var vulnerabilities []models.DependencyVuln
		err = f.DB.Preload("CVE").Find(&vulnerabilities, "asset_id = ? AND cve_id = ?", asset.ID, cve.CVE).Error
		assert.NoError(t, err)
		assert.Len(t, vulnerabilities, 1, "Should detect exactly one vulnerability")
		assert.Equal(t, cve.CVE, vulnerabilities[0].CVE.CVE, "Should detect correct CVE")
		assert.Equal(t, dtos.VulnStateOpen, vulnerabilities[0].State, "Vulnerability should be in open state")
	})
}

// TestScanAllAssetsFixesWithdrawnVulns tests that the scan fixes vulns whose cve was withdrawn
func TestScanAllAssetsFixesWithdrawnVulns(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-scan-reconcile")
		project := f.CreateProject(org.ID, "test-project-reconcile")
		asset := f.CreateAsset(project.ID, "test-asset-reconcile")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
		cve := models.CVE{
			CVE:              "CVE-2025-RECONCILE-001",
			DatePublished:    time.Now().Add(-24 * time.Hour),
			DateLastModified: time.Now().Add(-12 * time.Hour),
			Description:      "Test vulnerability for withdrawn cves",
			CVSS:             9.0,
		}
		err := f.DB.Create(&cve).Error
		assert.NoError(t, err)

		affectedComponent, err := createTestAffectedComponent("pkg:npm/reconcile-package@2.0.0", []models.CVE{cve})
		assert.NoError(t, err)
		err = f.DB.Create(&affectedComponent).Error
		assert.NoError(t, err)

		component := models.Component{
			ID: "pkg:npm/reconcile-package@2.0.0",
		}
		err = f.DB.Create(&component).Error
		assert.NoError(t, err)

		artifact := models.Artifact{
			ArtifactName:     "reconcile-test-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		err = SeedDirectDependencies(f.DB, assetVersion, artifact.ArtifactName, "pkg:npm/reconcile-package@2.0.0")
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.ScanAllAssets(context.Background())
		assert.NoError(t, err)

		var vulnerabilities []models.DependencyVuln
		err = f.DB.Find(&vulnerabilities, "asset_id = ? AND cve_id = ?", asset.ID, cve.CVE).Error
		assert.NoError(t, err)
		assert.Len(t, vulnerabilities, 1, "Should detect exactly one vulnerability")
		assert.Equal(t, dtos.VulnStateOpen, vulnerabilities[0].State, "Vulnerability should be in open state")

		err = f.DB.Exec(`UPDATE cves SET withdrawn = now() WHERE cve = ?`, cve.CVE).Error
		assert.NoError(t, err)
		err = runner.ScanAllAssets(context.Background())
		assert.NoError(t, err)

		var fixed models.DependencyVuln
		err = f.DB.First(&fixed, "id = ?", vulnerabilities[0].ID).Error
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateFixed, fixed.State, "Vulnerability should be fixed once the cve is withdrawn")

		var events []models.VulnEvent
		err = f.DB.Find(&events, "dependency_vuln_id = ? AND type = ?", fixed.ID, dtos.EventTypeFixed).Error
		assert.NoError(t, err)
		assert.Len(t, events, 1, "Should create exactly one fixed event")
		assert.False(t, events[0].CreatedAt.IsZero(), "Fixed event should have a creation time")
	})
}
