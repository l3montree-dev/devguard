package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCVEForFixedVersion creates a CVE which can be referenced by affected components and dependency vulns
func createTestCVEForFixedVersion(f *TestFixture, cveID string) models.CVE {
	f.T.Helper()

	cve := models.CVE{
		CVE:              cveID,
		DatePublished:    time.Now().Add(-24 * time.Hour),
		DateLastModified: time.Now().Add(-12 * time.Hour),
		Description:      "Test vulnerability for fixed version daemon testing",
		CVSS:             7.5,
	}
	require.NoError(f.T, f.DB.Create(&cve).Error)
	return cve
}

// createTestDependencyVuln creates a dependency vuln with a specific component fixed version state.
// pass nil for fixedVersion to create a vuln the daemon has to pick up
func createTestDependencyVuln(f *TestFixture, asset models.Asset, assetVersion models.AssetVersion, cveID string, purl string, fixedVersion *string) models.DependencyVuln {
	f.T.Helper()

	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			State:            dtos.VulnStateOpen,
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		},
		CVEID:                 cveID,
		ComponentPurl:         purl,
		ComponentFixedVersion: fixedVersion,
	}
	require.NoError(f.T, f.DB.Create(&dependencyVuln).Error)
	return dependencyVuln
}

// fetchComponentFixedVersion reloads a single dependency vuln and returns its current fixed version
func fetchComponentFixedVersion(f *TestFixture, dependencyVuln models.DependencyVuln) *string {
	f.T.Helper()

	var reloaded models.DependencyVuln
	require.NoError(f.T, f.DB.First(&reloaded, "id = ?", dependencyVuln.ID).Error)
	return reloaded.ComponentFixedVersion
}

// TestFixedVersionDaemonUpdateFixedVersions tests the full daemon run from fetching the vulns up to the bulk update
func TestFixedVersionDaemonUpdateFixedVersions(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-fixed-version")
		project := f.CreateProject(org.ID, "test-project-fixed-version")
		asset := f.CreateAsset(project.ID, "test-asset-fixed-version")
		mainVersion := f.CreateAssetVersion(asset.ID, "main", true)
		devVersion := f.CreateAssetVersion(asset.ID, "dev", false)

		fixablePurl := "pkg:npm/fixable-package@1.0.0"
		unaffectedPurl := "pkg:npm/unaffected-package@1.0.0"

		// this cve has an affected component carrying a fix
		fixableCVE := createTestCVEForFixedVersion(f, "CVE-2025-FIXVER-001")
		affectedComponent, err := createTestAffectedComponent(fixablePurl, []models.CVE{fixableCVE})
		assert.NoError(t, err)
		affectedComponent.SemverFixed = new("1.2.3")
		assert.NoError(t, f.DB.Create(&affectedComponent).Error)

		// this cve affects the same purl but is not referenced by any affected component
		unmatchedCVE := createTestCVEForFixedVersion(f, "CVE-2025-FIXVER-002")
		// this cve already has a fixed version and no affected component at all
		alreadyFixedCVE := createTestCVEForFixedVersion(f, "CVE-2025-FIXVER-003")

		nullFixedVersionVuln := createTestDependencyVuln(f, asset, mainVersion, fixableCVE.CVE, fixablePurl, nil)
		emptyFixedVersionVuln := createTestDependencyVuln(f, asset, devVersion, fixableCVE.CVE, fixablePurl, new(""))
		unmatchedCVEVuln := createTestDependencyVuln(f, asset, mainVersion, unmatchedCVE.CVE, fixablePurl, nil)
		alreadyFixedVuln := createTestDependencyVuln(f, asset, mainVersion, alreadyFixedCVE.CVE, unaffectedPurl, new("9.9.9"))

		runner := f.CreateDaemonRunner()
		ctx := context.Background()

		fixedVersionJobs, err := runner.FetchVulnsToUpdate(ctx)
		assert.NoError(t, err)
		assert.NoError(t, runner.UpdateFixedVersions(ctx))

		t.Run("should deduplicate vulns sharing the same purl and cve", func(t *testing.T) {
			// three vulns are missing their fixed version, two of them share purl + cve
			assert.Len(t, fixedVersionJobs, 2)
		})

		t.Run("should set the fixed version on every vuln missing one", func(t *testing.T) {
			assert.Equal(t, new("1.2.3"), fetchComponentFixedVersion(f, nullFixedVersionVuln))
			assert.Equal(t, new("1.2.3"), fetchComponentFixedVersion(f, emptyFixedVersionVuln))
		})

		t.Run("should not set a fixed version if the affected component belongs to another cve", func(t *testing.T) {
			assert.Nil(t, fetchComponentFixedVersion(f, unmatchedCVEVuln))
		})

		t.Run("should leave vulns which already have a fixed version untouched", func(t *testing.T) {
			assert.Equal(t, new("9.9.9"), fetchComponentFixedVersion(f, alreadyFixedVuln))
		})

		t.Run("should update again on a second daemon run", func(t *testing.T) {
			// the staging table is created per transaction, a second run must not collide with the first one
			assert.NoError(t, f.DB.Model(&models.DependencyVuln{}).Where("id = ?", nullFixedVersionVuln.ID).
				Updates(map[string]any{"component_fixed_version": nil}).Error)

			assert.NoError(t, runner.UpdateFixedVersions(ctx))
			assert.Equal(t, new("1.2.3"), fetchComponentFixedVersion(f, nullFixedVersionVuln))
		})
	})
}
