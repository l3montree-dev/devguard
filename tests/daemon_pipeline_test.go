package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// createSBOMStructure creates a complete SBOM tree structure for testing
// This includes: artifact root, info source, and component dependencies
func createSBOMStructure(f *TestFixture, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, componentPurls []string, origin string) error {
	// Create artifact root component (needed for FK constraint)
	artifactRoot := "artifact:" + artifact.ArtifactName
	if err := f.DB.Create(&models.Component{ID: artifactRoot}).Error; err != nil {
		return err
	}

	// Create info source component (needed for FK constraint)
	infoSourceID := "sbom:" + origin + "@" + artifact.ArtifactName
	if err := f.DB.Create(&models.Component{ID: infoSourceID}).Error; err != nil {
		return err
	}

	// Create artifact root node dependency (NULL -> artifact:name)
	artifactRootDep := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		ComponentID:      "ROOT",
		DependencyID:     artifactRoot,
	}
	if err := f.DB.Create(&artifactRootDep).Error; err != nil {
		return err
	}

	// Create info source dependency (artifact:name -> sbom:origin@artifact)
	infoSourceDep := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		ComponentID:      artifactRoot,
		DependencyID:     infoSourceID,
	}
	if err := f.DB.Create(&infoSourceDep).Error; err != nil {
		return err
	}

	// Create component dependencies (sbom:origin@artifact -> pkg:...)
	for _, purl := range componentPurls {
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			ComponentID:      infoSourceID,
			DependencyID:     purl,
		}
		if err := f.DB.Create(&componentDependency).Error; err != nil {
			return err
		}
	}

	return nil
}

// createVEXStructure creates a VEX info source and links vulnerabilities to components
// This simulates a VEX document that reports specific CVEs affecting specific components
func createVEXStructure(f *TestFixture, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, componentPurls []string, cves []string, origin string) error {
	// Create artifact root (should already exist but check)
	artifactRoot := "artifact:" + artifact.ArtifactName

	// Create VEX info source component (needed for FK constraint)
	vexInfoSourceID := "vex:" + origin + "@" + artifact.ArtifactName
	if err := f.DB.Create(&models.Component{ID: vexInfoSourceID}).Error; err != nil {
		return err
	}

	// Create VEX info source dependency (artifact:name -> vex:origin@artifact)
	vexInfoSourceDep := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		ComponentID:      artifactRoot,
		DependencyID:     vexInfoSourceID,
	}
	if err := f.DB.Create(&vexInfoSourceDep).Error; err != nil {
		return err
	}

	// Create component dependencies from VEX to affected components
	// This represents the VEX document saying "these components have vulnerabilities"
	for _, purl := range componentPurls {
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			ComponentID:      vexInfoSourceID,
			DependencyID:     purl,
		}
		if err := f.DB.Create(&componentDependency).Error; err != nil {
			return err
		}
	}

	return nil
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
			asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
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

			// Create artifact root component (needed for FK constraint)
			artifactRoot := "artifact:" + artifact.ArtifactName
			err = f.DB.Create(&models.Component{ID: artifactRoot}).Error
			assert.NoError(t, err)

			// Create artifact root node dependency (NULL -> artifact:name)
			artifactRootDep := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				ComponentID:      "ROOT",
				DependencyID:     artifactRoot,
			}
			err = f.DB.Create(&artifactRootDep).Error
			assert.NoError(t, err)

			// Create component dependency (artifact:name -> pkg:...)
			componentDependency := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				ComponentID:      artifactRoot,
				DependencyID:     "pkg:npm/test-package@1.0.0",
				Dependency:       component,
			}
			err = f.DB.Create(&componentDependency).Error
			assert.NoError(t, err)

			// Run the daemon pipeline for this specific asset
			runner := f.CreateDaemonRunner()
			err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
			assert.NoError(t, err)

			// Verify asset was updated with pipeline run time
			var updatedAsset models.Asset
			err = f.DB.First(&updatedAsset, "id = ?", asset.ID).Error
			assert.NoError(t, err)
			assert.True(t, updatedAsset.PipelineLastRun.After(time.Now().Add(-1*time.Minute)), "PipelineLastRun should be recent")
			assert.Nil(t, updatedAsset.PipelineError, "Pipeline should complete without errors")

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

// TestDaemonPipelineAutoReopenExceedThreshold tests that vulnerabilities are reopened when they exceed the threshold
func TestDaemonPipelineAutoReopenExceedThreshold(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-reopen-exceed")
		project := f.CreateProject(org.ID, "test-project-reopen-exceed")
		asset := f.CreateAsset(project.ID, "test-asset-reopen-exceed")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Configure auto-reopen after 1 day
		autoReopenDays := 1
		asset.VulnAutoReopenAfterDays = &autoReopenDays
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err := f.App.AssetRepository.Save(context.Background(), nil, &asset)
		assert.NoError(t, err)

		// Create a CVE
		cve := models.CVE{
			CVE:  "CVE-2025-TEST-002",
			CVSS: 7.5,
		}
		err = f.DB.Create(&cve).Error
		assert.NoError(t, err)

		// Create affected component (links CVE to the component PURL)
		affectedComponent, err := createTestAffectedComponent("pkg:npm/test-package@1.0.0", []models.CVE{cve})
		assert.NoError(t, err)
		err = f.DB.Create(&affectedComponent).Error
		assert.NoError(t, err)

		// Create artifact
		artifact := models.Artifact{
			ArtifactName:     "test-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		// Create component
		component := models.Component{
			ID: "pkg:npm/test-package@1.0.0",
		}
		err = f.DB.Create(&component).Error
		assert.NoError(t, err)

		// Create SBOM structure
		err = createSBOMStructure(f, asset, assetVersion, artifact, []string{"pkg:npm/test-package@1.0.0"}, "test-origin")
		assert.NoError(t, err)

		// Create VEX structure that reports the CVE for this component
		err = createVEXStructure(f, asset, assetVersion, artifact, []string{"pkg:npm/test-package@1.0.0"}, []string{cve.CVE}, "test-origin")
		assert.NoError(t, err)

		// Create the vulnerability in accepted state (2 days ago)
		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateAccepted,
				LastDetected:     time.Now().Add(-48 * time.Hour),
			},
			CVEID:             cve.CVE,
			ComponentPurl:     "pkg:npm/test-package@1.0.0",
			VulnerabilityPath: []string{"pkg:npm/test-package@1.0.0"},
			Artifacts:         []models.Artifact{artifact},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		// Create accepted event (2 days ago)
		acceptEvent := models.NewAcceptedEvent(
			vulnerability.ID,
			dtos.VulnTypeDependencyVuln,
			"test-user",
			"Test acceptance",
			false,
			nil,
		)
		acceptEvent.CreatedAt = time.Now().Add(-48 * time.Hour)
		err = f.DB.Create(&acceptEvent).Error
		assert.NoError(t, err)

		// Run the full pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err)

		// Verify vulnerability was reopened
		var updatedVuln models.DependencyVuln
		err = f.DB.Preload("Events").First(&updatedVuln, "id = ?", vulnerability.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateOpen, updatedVuln.State, "Vulnerability should be reopened")

		// Verify reopen event was created
		var reopenEvent *models.VulnEvent
		for i := range updatedVuln.Events {
			if updatedVuln.Events[i].Type == dtos.EventTypeReopened {
				reopenEvent = &updatedVuln.Events[i]
				break
			}
		}
		assert.NotNil(t, reopenEvent, "Should have a reopen event")
		assert.Equal(t, "system", reopenEvent.UserID, "Should be reopened by system")
	})
}

// TestDaemonPipelineAutoReopenWithinThreshold tests that vulnerabilities are not reopened within the threshold
func TestDaemonPipelineAutoReopenWithinThreshold(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-reopen-within")
		project := f.CreateProject(org.ID, "test-project-reopen-within")
		asset := f.CreateAsset(project.ID, "test-asset-reopen-within")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Configure auto-reopen after 7 days
		autoReopenDays := 7
		asset.VulnAutoReopenAfterDays = &autoReopenDays
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err := f.App.AssetRepository.Save(context.Background(), nil, &asset)
		assert.NoError(t, err)

		// Create a CVE
		cve := models.CVE{
			CVE:  "CVE-2025-TEST-003",
			CVSS: 7.5,
		}
		err = f.DB.Create(&cve).Error
		assert.NoError(t, err)

		// Create affected component (links CVE to the component PURL)
		affectedComponent, err := createTestAffectedComponent("pkg:npm/test-package@1.0.0", []models.CVE{cve})
		assert.NoError(t, err)
		err = f.DB.Create(&affectedComponent).Error
		assert.NoError(t, err)

		// Create artifact
		artifact := models.Artifact{
			ArtifactName:     "test-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		// Create component
		component := models.Component{
			ID: "pkg:npm/test-package@1.0.0",
		}
		err = f.DB.Create(&component).Error
		assert.NoError(t, err)

		// Create SBOM structure
		err = createSBOMStructure(f, asset, assetVersion, artifact, []string{"pkg:npm/test-package@1.0.0"}, "test-origin")
		assert.NoError(t, err)

		// Create VEX structure that reports the CVE for this component
		err = createVEXStructure(f, asset, assetVersion, artifact, []string{"pkg:npm/test-package@1.0.0"}, []string{cve.CVE}, "test-origin")
		assert.NoError(t, err)

		// Create vulnerability accepted 2 days ago (within 7 day threshold)
		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateAccepted,
				LastDetected:     time.Now().Add(-48 * time.Hour),
			},
			CVEID:             cve.CVE,
			ComponentPurl:     "pkg:npm/test-package@1.0.0",
			VulnerabilityPath: []string{"pkg:npm/test-package@1.0.0"},
			Artifacts:         []models.Artifact{artifact},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		// Run the full pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err)

		// Verify vulnerability is still accepted
		var updatedVuln models.DependencyVuln
		err = f.DB.First(&updatedVuln, "id = ?", vulnerability.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateAccepted, updatedVuln.State, "Vulnerability should remain accepted")
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

// TestDaemonPipelineErrorHandlingRecordErrors tests that pipeline errors are recorded on assets
func TestDaemonPipelineErrorHandlingRecordErrors(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create an asset without required related entities to trigger an error
		org := f.CreateOrg("test-org-error-handling")
		project := f.CreateProject(org.ID, "test-project-error")
		asset := models.Asset{
			Name:            "test-asset",
			ProjectID:       project.ID,
			Slug:            "test-asset",
			PipelineLastRun: time.Now().Add(-2 * time.Hour),
		}
		err := f.DB.Create(&asset).Error
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err, "Pipeline should complete even with errors")
		// The pipeline should complete but may record errors
		var updatedAsset models.Asset
		err = f.DB.First(&updatedAsset, "id = ?", asset.ID).Error
		assert.NoError(t, err)

		// Pipeline should have run (timestamp updated)
		assert.True(t, updatedAsset.PipelineLastRun.After(asset.PipelineLastRun), "Pipeline should have updated run time")
	})
}

// TestDaemonPipelineFetchAssetIDsNeedProcessing tests fetching only assets that need processing
func TestDaemonPipelineFetchAssetIDsNeedProcessing(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create assets with different pipeline run times
		org := f.CreateOrg("test-org-fetch-ids")
		project := f.CreateProject(org.ID, "test-project-fetch")

		// Asset 1: Needs processing (old)
		asset1 := models.Asset{
			Name:            "asset-needs-processing",
			ProjectID:       project.ID,
			Slug:            "asset-needs-processing",
			PipelineLastRun: time.Now().Add(-20 * time.Hour),
		}
		err := f.DB.Create(&asset1).Error
		assert.NoError(t, err)

		// Asset 2: Recently processed (should be skipped)
		asset2 := models.Asset{
			Name:            "asset-recently-processed",
			ProjectID:       project.ID,
			Slug:            "asset-recently-processed",
			PipelineLastRun: time.Now().Add(-30 * time.Minute),
		}
		err = f.DB.Create(&asset2).Error
		assert.NoError(t, err)

		// Fetch asset IDs
		runner := f.CreateDaemonRunner()
		idsChan := runner.FetchAssetIDs(context.Background())

		// Collect IDs
		var ids []uuid.UUID
		for id := range idsChan {
			ids = append(ids, id)
		}

		// Should only include asset1
		assert.Contains(t, ids, asset1.ID, "Should include asset that needs processing")
		assert.NotContains(t, ids, asset2.ID, "Should not include recently processed asset")
	})
}

// TestDaemonPipelineFetchAssetIDsAll tests fetching all assets when none processed recently
func TestDaemonPipelineFetchAssetIDsAll(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-fetch-all")
		project := f.CreateProject(org.ID, "test-project-fetch-all")

		// Create multiple assets that all need processing
		assetIDs := make([]uuid.UUID, 0)
		for i := range 5 {
			asset := models.Asset{
				Name:            fmt.Sprintf("asset-%d", i),
				ProjectID:       project.ID,
				Slug:            fmt.Sprintf("asset-%d", i),
				PipelineLastRun: time.Now().Add(-30 * time.Hour),
			}
			err := f.DB.Create(&asset).Error
			assert.NoError(t, err)
			assetIDs = append(assetIDs, asset.ID)
		}

		// Fetch asset IDs
		runner := f.CreateDaemonRunner()
		idsChan := runner.FetchAssetIDs(context.Background())

		// Collect IDs
		var fetchedIDs []uuid.UUID
		for id := range idsChan {
			fetchedIDs = append(fetchedIDs, id)
		}

		// Should include all created assets
		for _, expectedID := range assetIDs {
			assert.Contains(t, fetchedIDs, expectedID, fmt.Sprintf("Should include asset %s", expectedID))
		}
	})
}

// TestDaemonPipelineScanAssetDetectVulns tests scanning assets and detecting vulnerabilities
func TestDaemonPipelineScanAssetDetectVulns(t *testing.T) {
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

		// create the component for artifact root node
		artifactRootID := "artifact:" + artifact.ArtifactName
		err = f.DB.Create(&models.Component{ID: artifactRootID}).Error
		assert.NoError(t, err)

		// Create artifact root node dependency (NULL -> artifact:name)
		artifactRoot := "artifact:" + artifact.ArtifactName
		artifactRootDep := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			ComponentID:      "ROOT",
			DependencyID:     artifactRoot,
		}
		err = f.DB.Create(&artifactRootDep).Error
		assert.NoError(t, err)

		// Create component dependency (artifact:name -> pkg:...)
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			ComponentID:      artifactRoot,
			DependencyID:     "pkg:npm/vulnerable-package@2.0.0",
			Dependency:       component,
		}
		err = f.DB.Create(&componentDependency).Error
		assert.NoError(t, err)

		// Mark asset for processing
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err = f.App.AssetRepository.Save(context.Background(), nil, &asset)
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
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

// TestDaemonPipelineScanAssetEmptyComponents tests handling assets with no components
func TestDaemonPipelineScanAssetEmptyComponents(t *testing.T) {
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

		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
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

		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
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

			// create the component for artifact root node
			artifactRootID := "artifact:" + artifact.ArtifactName
			err = f.DB.Create(&models.Component{ID: artifactRootID}).Error
			assert.NoError(t, err)

			// Create artifact root node dependency (NULL -> artifact:name)
			artifactRoot := "artifact:" + artifact.ArtifactName
			artifactRootDep := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				ComponentID:      "ROOT",
				DependencyID:     artifactRoot,
			}
			err = f.DB.Create(&artifactRootDep).Error
			assert.NoError(t, err)

			// Create component dependency (artifact:name -> pkg:...)
			componentDependency := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				ComponentID:      artifactRoot,
				DependencyID:     "pkg:npm/risk-test-package@1.0.0",
				Dependency:       component,
			}
			err = f.DB.Create(&componentDependency).Error
			assert.NoError(t, err)

			err = f.App.AssetRepository.Save(context.Background(), nil, &asset)
			assert.NoError(t, err)

			// Run the pipeline
			runner := f.CreateDaemonRunner()
			err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
			assert.NoError(t, err)

			// Verify vulnerability was detected and risk was calculated
			var vulnerabilities []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND cve_id = ?", asset.ID, cve.CVE).Find(&vulnerabilities).Error
			assert.NoError(t, err)
			assert.Greater(t, len(vulnerabilities), 0, "Should detect vulnerability")

			vuln := vulnerabilities[0]
			assert.NotNil(t, vuln.RawRiskAssessment, "Risk assessment should be calculated")
			assert.Greater(t, *vuln.RawRiskAssessment, float64(3), "Risk should be calculated (can be 0 or greater)")
		})
	})
}

func TestDaemonPipelineApplySystemVEXRules(t *testing.T) {

	package1 := "pkg:npm/test-package@1.0.0"
	package2 := "pkg:npm/test-package@2.0.0"
	lib1 := "pkg:npm/test-lib@1.0.0"
	lib2 := "pkg:npm/test-lib@2.0.0"
	vulnLib1 := "pkg:npm/test-vulnerableLib@1.0.0"
	vulnLib2 := "pkg:npm/test-vulnerableLib@2.0.0"

	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should apply systemVEXRules to existing vulns if path matches", func(t *testing.T) {
			org1 := f.CreateOrg("test-org-1")
			project1 := f.CreateProject(org1.ID, "test-project-1")
			asset1 := f.CreateAsset(project1.ID, "test-asset-1")
			assetVersion1 := f.CreateAssetVersion(asset1.ID, "main", true)

			cve1 := models.CVE{
				CVE:  "CVE-2025-TEST-001",
				CVSS: 7.5,
			}

			err := f.DB.Create(&cve1).Error
			assert.NoError(t, err)

			vulnerability1 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}

			err = f.DB.Create(&vulnerability1).Error
			assert.NoError(t, err)

			systemVEXRule1 := models.SystemVEXRule{
				// Composite key components
				CVEID:     cve1.CVE,
				VexSource: "https://test-cve.com",

				// Rule data
				EventType:               dtos.EventTypeFalsePositive,
				MechanicalJustification: dtos.ComponentNotPresent,
				PathPattern:             dtos.PathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1}),
				CreatedByID:             "system",
			}
			systemVEXRule1.SetPathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1})

			err = f.DB.Create(&systemVEXRule1).Error
			assert.NoError(t, err)

			runner := f.CreateDaemonRunner()
			err = runner.ApplySystemVEXRules(context.Background())
			assert.NoError(t, err)

			var createdDependencyVuln models.DependencyVuln
			err = f.DB.First(&createdDependencyVuln).Error
			assert.NoError(t, err)

			// Idea is, if the SystemVEXRule is properly created/applied, there should be only one DependencyVuln with the corresponding CVEID
			var createdVulnEvents []models.VulnEvent
			err = f.DB.Find(&createdVulnEvents, "dependency_vuln_id = ?", createdDependencyVuln.Vulnerability.ID).Error
			assert.NoError(t, err)
			assert.Equal(t, 1, len(createdVulnEvents))
			assert.Equal(t, dtos.ComponentNotPresent, createdVulnEvents[0].MechanicalJustification)
			assert.Equal(t, "system", createdVulnEvents[0].UserID)
		})
	})

	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should not apply systemVEXRules to existing vulns if paths don't match", func(t *testing.T) {
			org1 := f.CreateOrg("test-org-1")
			project1 := f.CreateProject(org1.ID, "test-project-1")
			asset1 := f.CreateAsset(project1.ID, "test-asset-1")
			assetVersion1 := f.CreateAssetVersion(asset1.ID, "main", true)

			cve1 := models.CVE{
				CVE:  "CVE-2025-TEST-001",
				CVSS: 7.5,
			}

			err := f.DB.Create(&cve1).Error
			assert.NoError(t, err)

			cve2 := models.CVE{
				CVE:  "CVE-2025-TEST-002",
				CVSS: 3.5,
			}

			err = f.DB.Create(&cve2).Error
			assert.NoError(t, err)

			vulnerability2 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve2.CVE,
				ComponentPurl:     vulnLib2,
				VulnerabilityPath: []string{package2, lib2, vulnLib2},
				Artifacts:         []models.Artifact{},
			}

			err = f.DB.Create(&vulnerability2).Error
			assert.NoError(t, err)

			systemVEXRule1 := models.SystemVEXRule{
				// Composite key components
				CVEID:     cve1.CVE,
				VexSource: "https://test-cve.com",

				// Rule data
				EventType:               dtos.EventTypeFalsePositive,
				MechanicalJustification: dtos.ComponentNotPresent,
				PathPattern:             dtos.PathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1}),
				CreatedByID:             "system",
			}
			systemVEXRule1.SetPathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1})

			err = f.DB.Create(&systemVEXRule1).Error
			assert.NoError(t, err)

			runner := f.CreateDaemonRunner()
			err = runner.ApplySystemVEXRules(context.Background())
			assert.NoError(t, err)

			var createdDependencyVuln models.DependencyVuln
			err = f.DB.First(&createdDependencyVuln).Error
			assert.NoError(t, err)

			// This should not be applied, so there should be no DependencyVulns here
			var createdVulnEvents []models.VulnEvent
			err = f.DB.Find(&createdVulnEvents, "dependency_vuln_id = ?", createdDependencyVuln.Vulnerability.ID).Error
			assert.NoError(t, err)
			assert.Equal(t, 0, len(createdVulnEvents))
		})
	})
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should apply systemVEXRules to existing vulns even with cve alias", func(t *testing.T) {
			org1 := f.CreateOrg("test-org-1")
			project1 := f.CreateProject(org1.ID, "test-project-1")
			asset1 := f.CreateAsset(project1.ID, "test-asset-1")
			assetVersion1 := f.CreateAssetVersion(asset1.ID, "main", true)

			cve1 := models.CVE{
				CVE:  "CVE-2025-TEST-001",
				CVSS: 7.5,
			}

			err := f.DB.Create(&cve1).Error
			assert.NoError(t, err)

			cve1Alias := models.CVE{
				CVE:  "CVE-2025-TEST-ALIAS-001",
				CVSS: 7.5,
			}

			err = f.DB.Create(&cve1Alias).Error
			assert.NoError(t, err)

			cveRelationship1 := models.CVERelationship{
				SourceCVE:        cve1.CVE,
				TargetCVE:        cve1Alias.CVE,
				RelationshipType: dtos.RelationshipTypeAlias,
			}

			err = f.DB.Create(&cveRelationship1).Error
			assert.NoError(t, err)

			vulnerabilityWithAlias := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1Alias.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}

			err = f.DB.Create(&vulnerabilityWithAlias).Error
			assert.NoError(t, err)

			systemVEXRule := models.SystemVEXRule{
				// Composite key components
				CVEID:     cve1.CVE,
				VexSource: "https://test-cve.com",

				// Rule data
				EventType:               dtos.EventTypeFalsePositive,
				MechanicalJustification: dtos.ComponentNotPresent,
				PathPattern:             dtos.PathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1}),
				CreatedByID:             "system",
			}
			systemVEXRule.SetPathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1})

			err = f.DB.Create(&systemVEXRule).Error
			assert.NoError(t, err)

			runner := f.CreateDaemonRunner()
			err = runner.ApplySystemVEXRules(context.Background())
			assert.NoError(t, err)

			var createdDependencyVuln models.DependencyVuln
			err = f.DB.First(&createdDependencyVuln, "cve_id = ?", cve1Alias.CVE).Error
			assert.NoError(t, err)

			// Idea is, if the SystemVEXRule is properly created/applied, there should be only one DependencyVuln with the corresponding CVEID
			var createdVulnEvents []models.VulnEvent
			err = f.DB.Find(&createdVulnEvents, "dependency_vuln_id = ?", createdDependencyVuln.Vulnerability.ID).Error
			assert.NoError(t, err)
			assert.Equal(t, 1, len(createdVulnEvents))
			assert.Equal(t, dtos.ComponentNotPresent, createdVulnEvents[0].MechanicalJustification)
			assert.Equal(t, "system", createdVulnEvents[0].UserID)
		})
	})
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		t.Run("should not apply systemVEXRules to existing vulns under paranoid mode", func(t *testing.T) {
			org1 := f.CreateOrg("test-org-1")
			project1 := f.CreateProject(org1.ID, "test-project-1")
			asset1 := models.Asset{
				Name:         "test-project-1",
				ProjectID:    project1.ID,
				ParanoidMode: true,
			}
			err := f.DB.Create(&asset1).Error
			require.NoError(f.T, err)
			assetVersion1 := f.CreateAssetVersion(asset1.ID, "main", true)

			cve1 := models.CVE{
				CVE:  "CVE-2025-TEST-001",
				CVSS: 7.5,
			}

			err = f.DB.Create(&cve1).Error
			assert.NoError(t, err)

			vulnerability1 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}

			err = f.DB.Create(&vulnerability1).Error
			assert.NoError(t, err)

			systemVEXRule1 := models.SystemVEXRule{
				// Composite key components
				CVEID:     cve1.CVE,
				VexSource: "https://test-cve.com",

				// Rule data
				EventType:               dtos.EventTypeFalsePositive,
				MechanicalJustification: dtos.ComponentNotPresent,
				PathPattern:             dtos.PathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1}),
				CreatedByID:             "system",
			}
			systemVEXRule1.SetPathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1})

			err = f.DB.Create(&systemVEXRule1).Error
			assert.NoError(t, err)

			runner := f.CreateDaemonRunner()
			err = runner.ApplySystemVEXRules(context.Background())
			assert.NoError(t, err)

			var createdDependencyVuln models.DependencyVuln
			err = f.DB.First(&createdDependencyVuln).Error
			assert.NoError(t, err)

			// This should not be applied, so there should be no DependencyVulns here
			var createdVulnEvents []models.VulnEvent
			err = f.DB.Find(&createdVulnEvents, "dependency_vuln_id = ?", createdDependencyVuln.Vulnerability.ID).Error
			assert.NoError(t, err)
			assert.Equal(t, 0, len(createdVulnEvents))
		})
	})
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("systemVEXRules should be applied for all assets that are not in paranoid mode and all vulns that are matching", func(t *testing.T) {
			org1 := f.CreateOrg("test-org-1")
			project1 := f.CreateProject(org1.ID, "test-project-1")
			asset1 := f.CreateAsset(project1.ID, "test-asset-1")
			assetVersion1 := f.CreateAssetVersion(asset1.ID, "main", true)

			org2 := f.CreateOrg("test-org-2")
			project2 := f.CreateProject(org2.ID, "test-project-2")
			asset2 := f.CreateAsset(project2.ID, "test-asset-2")
			assetVersion2 := f.CreateAssetVersion(asset2.ID, "main", true)

			org3 := f.CreateOrg("test-org-3")
			project3 := f.CreateProject(org3.ID, "test-project-3")
			asset3 := models.Asset{
				Name:         "test-project-3",
				ProjectID:    project3.ID,
				ParanoidMode: true,
			}
			err := f.DB.Create(&asset3).Error
			require.NoError(f.T, err)
			assetVersion3 := f.CreateAssetVersion(asset3.ID, "main", true)

			org4 := f.CreateOrg("test-org-4")
			project4 := f.CreateProject(org4.ID, "test-project-4")
			asset4 := f.CreateAsset(project4.ID, "test-asset-4")
			assetVersion4 := f.CreateAssetVersion(asset4.ID, "main", true)

			// Create CVEs
			cve1 := models.CVE{
				CVE:  "CVE-2025-TEST-001",
				CVSS: 7.5,
			}
			err = f.DB.Create(&cve1).Error
			assert.NoError(t, err)

			cve1Alias := models.CVE{
				CVE:  "CVE-2025-TEST-ALIAS-001",
				CVSS: 7.5,
			}
			err = f.DB.Create(&cve1Alias).Error
			assert.NoError(t, err)

			cve2 := models.CVE{
				CVE:  "CVE-2025-TEST-002",
				CVSS: 3.5,
			}
			err = f.DB.Create(&cve2).Error
			assert.NoError(t, err)

			cve2Alias1 := models.CVE{
				CVE:  "CVE-2025-TEST-ALIAS-102",
				CVSS: 4.9,
			}
			err = f.DB.Create(&cve2Alias1).Error
			assert.NoError(t, err)

			cve2Alias2 := models.CVE{
				CVE:  "CVE-2025-TEST-ALIAS-202",
				CVSS: 4.9,
			}
			err = f.DB.Create(&cve2Alias2).Error
			assert.NoError(t, err)

			// Create CVE Aliases
			cveRelationship1 := models.CVERelationship{
				SourceCVE:        "CVE-2025-TEST-001",
				TargetCVE:        "CVE-2025-TEST-ALIAS-001",
				RelationshipType: dtos.RelationshipTypeAlias,
			}
			err = f.DB.Create(&cveRelationship1).Error
			assert.NoError(t, err)

			cveRelationship2 := models.CVERelationship{
				SourceCVE:        "CVE-2025-TEST-002",
				TargetCVE:        "CVE-2025-TEST-ALIAS-102",
				RelationshipType: dtos.RelationshipTypeAlias,
			}
			err = f.DB.Create(&cveRelationship2).Error
			assert.NoError(t, err)

			cveRelationship3 := models.CVERelationship{
				SourceCVE:        "CVE-2025-TEST-002",
				TargetCVE:        "CVE-2025-TEST-ALIAS-202",
				RelationshipType: dtos.RelationshipTypeAlias,
			}
			err = f.DB.Create(&cveRelationship3).Error
			assert.NoError(t, err)

			vulnerability1 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability1).Error
			assert.NoError(t, err)

			vulnerability2 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset1.ID,
					AssetVersionName: assetVersion1.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve2.CVE,
				ComponentPurl:     vulnLib2,
				VulnerabilityPath: []string{package2, lib2, vulnLib2},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability2).Error
			assert.NoError(t, err)

			vulnerability3 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset2.ID,
					AssetVersionName: assetVersion2.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability3).Error
			assert.NoError(t, err)

			// Exists in different asset as vulnnerabilty1 and has a different CVE
			vulnerability4 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset2.ID,
					AssetVersionName: assetVersion2.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve2.CVE,
				ComponentPurl:     vulnLib2,
				VulnerabilityPath: []string{package2, lib2, vulnLib2},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability4).Error
			assert.NoError(t, err)

			vulnerability5 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset2.ID,
					AssetVersionName: assetVersion2.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve2Alias1.CVE,
				ComponentPurl:     vulnLib2,
				VulnerabilityPath: []string{package2, lib2, vulnLib2},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability5).Error
			assert.NoError(t, err)

			// Vuln created for asset3, this should not be matched since the asset is in paranoid mode
			vulnerability6 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset3.ID,
					AssetVersionName: assetVersion3.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib1, vulnLib1},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability6).Error
			assert.NoError(t, err)

			// Vuln created for asset4, alias test
			vulnerability7 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset4.ID,
					AssetVersionName: assetVersion4.Name,
					State:            dtos.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				CVEID:             cve1Alias.CVE,
				ComponentPurl:     vulnLib1,
				VulnerabilityPath: []string{package1, lib2, vulnLib1},
				Artifacts:         []models.Artifact{},
			}
			err = f.DB.Create(&vulnerability7).Error
			assert.NoError(t, err)

			//Create SystemVEXRules
			systemVEXRule1 := models.SystemVEXRule{
				// Composite key components
				CVEID:     cve1.CVE,
				VexSource: "https://test-cve.com",

				// Rule data
				EventType:               dtos.EventTypeFalsePositive,
				MechanicalJustification: dtos.ComponentNotPresent,
				PathPattern:             dtos.PathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1}),
				CreatedByID:             "system",
			}
			systemVEXRule1.SetPathPattern(dtos.PathPattern{package1, dtos.PathPatternWildcard, vulnLib1})

			err = f.DB.Create(&systemVEXRule1).Error
			assert.NoError(t, err)

			runner := f.CreateDaemonRunner()
			err = runner.ApplySystemVEXRules(context.Background())
			assert.NoError(t, err)

			var createdDependencyVulns []models.DependencyVuln
			err = f.DB.Find(&createdDependencyVulns).Error
			assert.NoError(t, err)

			var createdRels []models.CVERelationship
			err = f.DB.Find(&createdRels).Error
			assert.NoError(t, err)

			createdDependencyVulnsIDs := utils.Map(createdDependencyVulns, func(vuln models.DependencyVuln) uuid.UUID {
				return vuln.ID
			})

			// This should not be applied, so there should be no DependencyVulns here
			var createdVulnEvents []models.VulnEvent
			err = f.DB.Find(&createdVulnEvents, "dependency_vuln_id IN (?)", createdDependencyVulnsIDs).Error
			assert.NoError(t, err)
			assert.Equal(t, 3, len(createdVulnEvents))

			resultsMap := make(map[string]models.VulnEvent)
			for _, ve := range createdVulnEvents {
				resultsMap[ve.DependencyVulnID.String()] = ve
			}

			for _, dv := range createdDependencyVulns {
				if _, ok := resultsMap[dv.ID.String()]; !ok {
					continue
				}
				assert.Equal(t, dtos.ComponentNotPresent, resultsMap[dv.ID.String()].MechanicalJustification)
				assert.Equal(t, "system", resultsMap[dv.ID.String()].UserID)
			}
		})
	})

}
