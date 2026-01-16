package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
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
	namespace := purl.Namespace
	subpath := purl.Subpath

	return models.AffectedComponent{
		Source:             "test",
		PurlWithoutVersion: purlWithoutVersion,
		Ecosystem:          purl.Type,
		Scheme:             "pkg",
		Type:               purl.Type,
		Name:               purl.Name,
		Namespace:          &namespace,
		Qualifiers:         databasetypes.MustJSONBFromStruct(purl.Qualifiers.Map()),
		Subpath:            &subpath,
		Version:            &purl.Version,
		CVE:                cves,
	}, nil
}

// TestDaemonPipelineEndToEnd tests the complete pipeline flow from asset creation to all stages
func TestDaemonPipelineEndToEnd(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("should successfully process an asset through the entire pipeline", func(t *testing.T) {
			// Create test data
			org := f.CreateOrg("test-org-end-to-end")
			project := f.CreateProject(org.ID, "test-project-e2e")
			asset := f.CreateAsset(project.ID, "test-asset-e2e")
			assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
			asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
			err := f.App.AssetRepository.Save(nil, &asset)
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

			// Create component dependency
			componentDependency := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				Artifacts: []models.Artifact{
					artifact,
				},
				ComponentID:  nil,
				DependencyID: "pkg:npm/test-package@1.0.0",
				Dependency:   component,
			}
			err = f.DB.Create(&componentDependency).Error
			assert.NoError(t, err)

			// Run the daemon pipeline for this specific asset
			runner := f.CreateDaemonRunner()
			err = runner.RunDaemonPipelineForAsset(asset.ID)
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
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-reopen-exceed")
		project := f.CreateProject(org.ID, "test-project-reopen-exceed")
		asset := f.CreateAsset(project.ID, "test-asset-reopen-exceed")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Configure auto-reopen after 1 day
		autoReopenDays := 1
		asset.VulnAutoReopenAfterDays = &autoReopenDays
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err := f.App.AssetRepository.Save(nil, &asset)
		assert.NoError(t, err)

		// Create a vulnerability
		cve := models.CVE{
			CVE:  "CVE-2025-TEST-002",
			CVSS: 7.5,
		}
		err = f.DB.Create(&cve).Error
		assert.NoError(t, err)

		// create the component "pkg:npm/test-package@1.0.0"
		component := models.Component{
			ID: "pkg:npm/test-package@1.0.0",
		}

		assert.Nil(t, f.DB.Create(&component).Error)

		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateAccepted,
				LastDetected:     time.Now().Add(-48 * time.Hour), // 2 days ago
			},
			CVEID:         cve.CVE,
			ComponentPurl: "pkg:npm/test-package@1.0.0",
			Artifacts: []models.Artifact{{
				ArtifactName:     "test-artifact",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		// Create accepted event (2 days ago)
		acceptEvent := models.NewAcceptedEvent(
			vulnerability.ID,
			dtos.VulnTypeDependencyVuln,
			"test-user",
			"Test acceptance",
			dtos.UpstreamStateInternal,
		)
		acceptEvent.CreatedAt = time.Now().Add(-48 * time.Hour)
		err = f.DB.Create(&acceptEvent).Error
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(asset.ID)
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
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-reopen-within")
		project := f.CreateProject(org.ID, "test-project-reopen-within")
		asset := f.CreateAsset(project.ID, "test-asset-reopen-within")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Configure auto-reopen after 7 days
		autoReopenDays := 7
		asset.VulnAutoReopenAfterDays = &autoReopenDays
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err := f.App.AssetRepository.Save(nil, &asset)
		assert.NoError(t, err)

		// Create a vulnerability accepted 2 days ago (within 7 day threshold)
		cve := models.CVE{
			CVE:  "CVE-2025-TEST-003",
			CVSS: 7.5,
		}
		err = f.DB.Create(&cve).Error
		assert.NoError(t, err)

		// create the component "pkg:npm/test-package@1.0.0"
		component := models.Component{
			ID: "pkg:npm/test-package@1.0.0",
		}
		assert.Nil(t, f.DB.Create(&component).Error)

		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateAccepted,
				LastDetected:     time.Now().Add(-48 * time.Hour),
			},
			CVEID:         cve.CVE,
			ComponentPurl: "pkg:npm/test-package@1.0.0",
			Artifacts: []models.Artifact{{
				ArtifactName:     "test-artifact",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(asset.ID)
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
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		runner := f.CreateDaemonRunner()
		nonExistentID := uuid.New()

		err := runner.RunDaemonPipelineForAsset(nonExistentID)
		assert.Error(t, err, "Should return error for non-existent asset")
		assert.Contains(t, err.Error(), "could not fetch asset", "Error should indicate asset fetch failure")
	})
}

// TestDaemonPipelineErrorHandlingRecordErrors tests that pipeline errors are recorded on assets
func TestDaemonPipelineErrorHandlingRecordErrors(t *testing.T) {
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
		err = runner.RunDaemonPipelineForAsset(asset.ID)
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
		idsChan := runner.FetchAssetIDs()

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
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-fetch-all")
		project := f.CreateProject(org.ID, "test-project-fetch-all")

		// Create multiple assets that all need processing
		assetIDs := make([]uuid.UUID, 0)
		for i := 0; i < 5; i++ {
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
		idsChan := runner.FetchAssetIDs()

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

		// Create component dependency
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			Artifacts: []models.Artifact{
				artifact,
			},
			ComponentID:  nil,
			DependencyID: "pkg:npm/vulnerable-package@2.0.0",
			Dependency:   component,
		}
		err = f.DB.Create(&componentDependency).Error
		assert.NoError(t, err)

		// Mark asset for processing
		asset.PipelineLastRun = time.Now().Add(-2 * time.Hour)
		err = f.App.AssetRepository.Save(nil, &asset)
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(asset.ID)
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
		err = f.App.AssetRepository.Save(nil, &asset)
		assert.NoError(t, err)

		// Run the pipeline
		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(asset.ID)
		assert.NoError(t, err, "Should handle empty artifacts without error")

		// Verify no vulnerabilities were created
		var vulnerabilities []models.DependencyVuln
		err = f.DB.Find(&vulnerabilities, "asset_id = ?", asset.ID).Error
		assert.NoError(t, err)
		assert.Len(t, vulnerabilities, 0, "Should not create vulnerabilities for empty artifacts")
	})
}

// TestDaemonPipelineRiskCalculation tests the risk calculation stage
func TestDaemonPipelineRiskCalculation(t *testing.T) {
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
				EPSS:             utils.Ptr(0.7),
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

			// Create component dependency
			componentDependency := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				Artifacts: []models.Artifact{
					artifact,
				},
				ComponentID:  nil,
				DependencyID: "pkg:npm/risk-test-package@1.0.0",
				Dependency:   component,
			}
			err = f.DB.Create(&componentDependency).Error
			assert.NoError(t, err)

			err = f.App.AssetRepository.Save(nil, &asset)
			assert.NoError(t, err)

			// Run the pipeline
			runner := f.CreateDaemonRunner()
			err = runner.RunDaemonPipelineForAsset(asset.ID)
			assert.NoError(t, err)

			// Verify vulnerability was detected and risk was calculated
			var vulnerabilities []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND cve_id = ?", asset.ID, cve.CVE).Find(&vulnerabilities).Error
			assert.NoError(t, err)
			assert.Greater(t, len(vulnerabilities), 0, "Should detect vulnerability")

			vuln := vulnerabilities[0]
			assert.NotNil(t, vuln.RawRiskAssessment, "Risk assessment should be calculated")
			assert.Greater(t, *vuln.RawRiskAssessment, float64(7), "Risk should be calculated (can be 0 or greater)")
		})
	})
}
