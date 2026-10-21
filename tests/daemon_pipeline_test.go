package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

// createTestAffectedComponent creates a properly populated AffectedComponent for testing
func createTestAffectedComponent(purlStr string, cves []models.CVE) (models.AffectedComponent, error) {
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return models.AffectedComponent{}, err
	}

	purlWithoutVersion := normalize.ToPurlWithoutVersion(purl)

	return models.AffectedComponent{
		PurlWithoutVersion: purlWithoutVersion,
		Ecosystem:          purl.Type,
		Version:            &purl.Version,
		CVE:                cves,
	}, nil
}

// TestDaemonPipelineEndToEnd tests the complete pipeline flow from asset creation to all stages
func TestDaemonPipelineEndToEnd(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should successfully process an asset through the entire pipeline", func(t *testing.T) {
			// Create test data
			org := f.CreateOrg("test-org-end-to-end")
			project := f.CreateProject(org.ID, "test-project-e2e")
			asset := f.CreateAsset(project.ID, "test-asset-e2e")
			assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
			err := f.App.AssetRepository.Save(context.Background(), nil, &asset)
			assert.NoError(t, err)

			// Create a CVE and affected component
			cve := models.CVE{
				CVE:              "CVE-2025-TEST-001",
				DatePublished:    time.Now().Add(-24 * time.Hour),
				DateLastModified: time.Now().Add(-12 * time.Hour),
				Description:      "Test vulnerability for pipeline testing",
				CVSS:             8.5,
			}
			err = f.DB.Create(&cve).Error
			assert.NoError(t, err)

			affectedComponent, err := createTestAffectedComponent("pkg:npm/test-package@1.0.0", []models.CVE{cve})
			assert.NoError(t, err)
			err = f.DB.Create(&affectedComponent).Error
			assert.NoError(t, err)

			// Create component
			component := models.Component{
				ID: "pkg:npm/test-package@1.0.0",
			}
			err = f.DB.Create(&component).Error
			assert.NoError(t, err)

			// Create artifact
			artifact := models.Artifact{
				ArtifactName:     "test-artifact",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			err = f.DB.Create(&artifact).Error
			assert.NoError(t, err)

			err = SeedDirectDependencies(f.DB, assetVersion, artifact.ArtifactName, "pkg:npm/test-package@1.0.0")
			assert.NoError(t, err)

			// Run the daemon pipeline for this specific asset
			runner := f.CreateDaemonRunner()
			// the scan is a separate job, the pipeline only runs the per asset stages
			err = runner.ScanAllAssets(context.Background())
			assert.NoError(t, err)
			err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
			assert.NoError(t, err)

			// Verify vulnerabilities were detected
			var vulnerabilities []models.DependencyVuln
			err = f.DB.Find(&vulnerabilities, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.NoError(t, err)
			assert.Greater(t, len(vulnerabilities), 0, "Should detect at least one vulnerability")

			// Verify statistics were collected
			var stats []models.ArtifactRiskHistory
			err = f.DB.Find(&stats, "asset_id = ?", asset.ID).Error
			assert.NoError(t, err)
			assert.Greater(t, len(stats), 0, "Should have risk statistics")
		})
	})
}

// TestDaemonPipelineErrorHandlingMissingAsset tests error handling for non-existent assets
func TestDaemonPipelineErrorHandlingMissingAsset(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		runner := f.CreateDaemonRunner()
		nonExistentID := uuid.New()

		err := runner.RunDaemonPipelineForAsset(context.Background(), nonExistentID)
		assert.Error(t, err, "Should return error for non-existent asset")
		assert.Contains(t, err.Error(), "could not fetch asset", "Error should indicate asset fetch failure")
	})
}

// TestDaemonPipelineErrorHandlingAssetWithoutVersions tests that the pipeline completes for an asset without any asset versions
func TestDaemonPipelineErrorHandlingAssetWithoutVersions(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create an asset without any asset versions or artifacts
		org := f.CreateOrg("test-org-error-handling")
		project := f.CreateProject(org.ID, "test-project-error")
		asset := models.Asset{
			Name:      "test-asset",
			ProjectID: project.ID,
			Slug:      "test-asset",
		}
		err := f.DB.Create(&asset).Error
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err, "Pipeline should complete without asset versions")
	})
}

// TestDaemonPipelineEmptyArtifact tests that the pipeline handles artifacts without components
func TestDaemonPipelineEmptyArtifact(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-scan-empty")
		project := f.CreateProject(org.ID, "test-project-empty")
		asset := f.CreateAsset(project.ID, "test-asset-empty")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
		// Create artifact but no components
		artifact := models.Artifact{
			ArtifactName:     "empty-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err := f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		err = f.App.AssetRepository.Save(context.Background(), nil, &asset)
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err, "Should handle empty artifacts without error")

		// Verify no vulnerabilities were created
		var vulnerabilities []models.DependencyVuln
		err = f.DB.Find(&vulnerabilities, "asset_id = ?", asset.ID).Error
		assert.NoError(t, err)
		assert.Len(t, vulnerabilities, 0, "Should not create vulnerabilities for empty artifacts")
	})
}

// TestDaemonPipelineDeleteOldVersionsDoesNotCauseRiskHistoryFKViolation verifies that
// when DeleteOldAssetVersions removes a stale branch version (and its artifacts), the
// downstream CollectStats stage does not attempt to insert artifact_risk_history rows
// for those now-deleted artifacts, which would violate the fk_artifact constraint.
func TestDaemonPipelineDeleteOldVersionsDoesNotCauseRiskHistoryFKViolation(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-fk-violation")
		project := f.CreateProject(org.ID, "test-project-fk-violation")
		asset := f.CreateAsset(project.ID, "test-asset-fk-violation")

		// Main branch: survives DeleteOldAssetVersions
		mainVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Stale branch: last_accessed_at is 10 days ago → qualifies for deletion
		staleVersion := models.AssetVersion{
			Name:           "stale-branch",
			AssetID:        asset.ID,
			DefaultBranch:  false,
			Slug:           "stale-branch",
			Type:           models.AssetVersionBranch,
			LastAccessedAt: time.Now().AddDate(0, 0, -10),
		}
		err := f.DB.Create(&staleVersion).Error
		assert.NoError(t, err)

		// Give the stale branch an artifact so CollectStats has something to iterate
		staleArtifact := models.Artifact{
			ArtifactName:     "stale-artifact",
			AssetVersionName: staleVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&staleArtifact).Error
		assert.NoError(t, err)

		// Give the main branch an artifact too (to confirm it still works after the fix)
		mainArtifact := models.Artifact{
			ArtifactName:     "main-artifact",
			AssetVersionName: mainVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&mainArtifact).Error
		assert.NoError(t, err)

		err = f.App.AssetRepository.Save(context.Background(), nil, &asset)
		assert.NoError(t, err)

		// Running the pipeline must not error with:
		// "insert or update on table artifact_risk_history violates foreign key
		// constraint fk_artifact (SQLSTATE 23503)"
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err)

		// The stale version and its artifact must have been removed
		var remainingArtifacts []models.Artifact
		err = f.DB.Find(&remainingArtifacts, "asset_version_name = ? AND asset_id = ?", staleVersion.Name, asset.ID).Error
		assert.NoError(t, err)
		assert.Empty(t, remainingArtifacts, "stale branch artifacts must be deleted")

		// No orphaned risk history rows must exist for the deleted artifact
		var orphanedHistory []models.ArtifactRiskHistory
		err = f.DB.Find(&orphanedHistory, "artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
			staleArtifact.ArtifactName, staleVersion.Name, asset.ID).Error
		assert.NoError(t, err)
		assert.Empty(t, orphanedHistory, "must not have risk history for deleted artifact")
	})
}

// TestDaemonPipelineRiskCalculation tests the risk calculation stage
func TestDaemonPipelineRiskCalculation(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should recalculate risk for detected vulnerabilities", func(t *testing.T) {
			org := f.CreateOrg("test-org-risk-calc")
			project := f.CreateProject(org.ID, "test-project-risk")
			asset := f.CreateAsset(project.ID, "test-asset-risk")
			assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

			// Create CVE and affected component
			cve := models.CVE{
				CVE:              "CVE-2025-RISK-001",
				DatePublished:    time.Now().Add(-24 * time.Hour),
				DateLastModified: time.Now().Add(-12 * time.Hour),
				Description:      "Test vulnerability for risk calculation",
				CVSS:             8.5,
				Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				EPSS:             new(0.7),
			}
			err := f.DB.Create(&cve).Error
			assert.NoError(t, err)

			affectedComponent, err := createTestAffectedComponent("pkg:npm/risk-test-package@1.0.0", []models.CVE{cve})
			assert.NoError(t, err)
			err = f.DB.Create(&affectedComponent).Error
			assert.NoError(t, err)
			// Create component
			component := models.Component{
				ID: "pkg:npm/risk-test-package@1.0.0",
			}
			err = f.DB.Create(&component).Error
			assert.NoError(t, err)

			// Create artifact
			artifact := models.Artifact{
				ArtifactName:     "risk-test-artifact",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			err = f.DB.Create(&artifact).Error
			assert.NoError(t, err)

			err = SeedDirectDependencies(f.DB, assetVersion, artifact.ArtifactName, "pkg:npm/risk-test-package@1.0.0")
			assert.NoError(t, err)

			err = f.App.AssetRepository.Save(context.Background(), nil, &asset)
			assert.NoError(t, err)

			// Run the pipeline
			runner := f.CreateDaemonRunner()
			// the scan is a separate job, the pipeline only runs the per asset stages
			err = runner.ScanAllAssets(context.Background())
			assert.NoError(t, err)
			err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
			assert.NoError(t, err)

			// Verify vulnerability was detected and risk was calculated
			var vulnerabilities []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND cve_id = ?", asset.ID, cve.CVE).Find(&vulnerabilities).Error
			assert.NoError(t, err)
			assert.Greater(t, len(vulnerabilities), 0, "Should detect vulnerability")

			vuln := vulnerabilities[0]
			assert.NotNil(t, vuln.RiskAssessment, "Risk assessment should be calculated")
			assert.Greater(t, *vuln.RiskAssessment, float64(3), "Risk should be calculated (can be 0 or greater)")
		})
	})
}
