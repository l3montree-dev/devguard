// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact_test

import (
	"net/http/httptest"
	"testing"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestDeleteArtifactIntegration(t *testing.T) {
	// Initialize test database
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create artifact service and controller
	artifactRepository := repositories.NewArtifactRepository(db)
	cveRepository := mocks.NewCveRepository(t)
	componentRepository := repositories.NewComponentRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	assetVersionService := mocks.NewAssetVersionService(t)
	dependencyVulnService := mocks.NewDependencyVulnService(t)

	artifactService := artifact.NewService(artifactRepository, cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)
	controller := artifact.NewController(artifactRepository, artifactService)

	// Create test organization, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// Setup echo app
	app := echo.New()

	// Setup context helper
	setupContext := func(ctx core.Context, artifactToDelete models.Artifact) {
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetAssetVersion(ctx, assetVersion)
		core.SetArtifact(ctx, artifactToDelete)
	}

	t.Run("should successfully delete an existing artifact", func(t *testing.T) {
		// Create a test artifact
		testArtifact := models.Artifact{
			ArtifactName:     "test-artifact-delete",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err := db.Create(&testArtifact).Error
		assert.NoError(t, err)

		// Verify artifact exists before deletion
		var existingArtifact models.Artifact
		err = db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
			testArtifact.ArtifactName, testArtifact.AssetVersionName, testArtifact.AssetID).
			First(&existingArtifact).Error
		assert.NoError(t, err)
		assert.Equal(t, testArtifact.ArtifactName, existingArtifact.ArtifactName)

		// Setup HTTP request and response
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/artifacts/"+testArtifact.ArtifactName, nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx, testArtifact)

		// Execute the delete operation
		err = controller.DeleteArtifact(ctx)

		// Verify the operation succeeded
		assert.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)

		// Verify artifact was actually deleted from database
		var deletedArtifact models.Artifact
		err = db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
			testArtifact.ArtifactName, testArtifact.AssetVersionName, testArtifact.AssetID).
			First(&deletedArtifact).Error
		assert.Error(t, err) // Should not find the artifact
		assert.Contains(t, err.Error(), "record not found")
	})

	t.Run("should handle deletion of artifact with dependencies", func(t *testing.T) {
		// Create a test artifact with some related data
		testArtifact := models.Artifact{
			ArtifactName:     "test-artifact-with-deps",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err := db.Create(&testArtifact).Error
		assert.NoError(t, err)

		// Create a component that might be associated with this artifact
		testComponent := models.Component{
			Purl:    "pkg:npm/test-component@1.0.0",
			Version: "1.0.0",
		}
		err = db.Create(&testComponent).Error
		assert.NoError(t, err)

		// Create a CVE record first (required by foreign key constraint)
		testCVE := models.CVE{
			CVE:         "CVE-2024-12345",
			Description: "Test CVE for integration testing",
			CVSS:        7.5,
		}
		err = db.Create(&testCVE).Error
		assert.NoError(t, err)

		// Create a dependency vulnerability that might be linked to the artifact
		testDepVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
				State:            models.VulnStateOpen,
			},
			CVEID:         &testCVE.CVE,
			ComponentPurl: &testComponent.Purl,
		}
		err = db.Create(&testDepVuln).Error
		assert.NoError(t, err)

		// Associate the artifact with the dependency vulnerability (many-to-many relationship)
		err = db.Model(&testDepVuln).Association("Artifacts").Append(&testArtifact)
		assert.NoError(t, err)

		// Verify association exists before deletion
		artifactCount := db.Model(&testDepVuln).Association("Artifacts").Count()
		assert.Equal(t, int64(1), artifactCount)

		// Setup HTTP request and response
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/artifacts/"+testArtifact.ArtifactName, nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx, testArtifact)

		// Execute the delete operation
		err = controller.DeleteArtifact(ctx)

		// Verify the operation succeeded
		assert.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)

		// Verify artifact was deleted
		var deletedArtifact models.Artifact
		err = db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
			testArtifact.ArtifactName, testArtifact.AssetVersionName, testArtifact.AssetID).
			First(&deletedArtifact).Error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "record not found")

		// Verify artifact associations were cleaned up (many-to-many table should be cleaned up automatically)
		artifactCountAfter := db.Model(&testDepVuln).Association("Artifacts").Count()
		assert.Equal(t, int64(0), artifactCountAfter) // Association should be gone due to CASCADE delete
	})

	t.Run("should return error when artifact service fails", func(t *testing.T) {
		// Create a test artifact but don't save it to DB (non-existent)
		testArtifact := models.Artifact{
			ArtifactName:     "test-artifact-fail",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}

		// Create a separate test database connection that will be closed
		failingDB, terminateFailingDB := integration_tests.InitDatabaseContainer("../../../initdb.sql")
		terminateFailingDB() // Close the database connection to simulate a failure

		failingRepository := repositories.NewArtifactRepository(failingDB)
		failingService := artifact.NewService(failingRepository, cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)
		failingController := artifact.NewController(failingRepository, failingService)

		// Setup HTTP request and response
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/artifacts/"+testArtifact.ArtifactName, nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx, testArtifact)

		// Execute the delete operation - this should fail due to closed DB connection
		err := failingController.DeleteArtifact(ctx)

		// Verify the operation failed as expected
		assert.Error(t, err)
	})

	t.Run("should handle deletion of non-existent artifact gracefully", func(t *testing.T) {
		// Create artifact object that doesn't exist in database
		nonExistentArtifact := models.Artifact{
			ArtifactName:     "non-existent-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}

		// Setup HTTP request and response
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/artifacts/"+nonExistentArtifact.ArtifactName, nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx, nonExistentArtifact)

		// Execute the delete operation
		err := controller.DeleteArtifact(ctx)

		// Verify the operation succeeds (idempotent behavior)
		assert.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)
	})

	t.Run("should handle multiple artifacts with same name in different asset versions", func(t *testing.T) {
		// Create another asset version
		anotherAssetVersion := models.AssetVersion{
			Name:          "feature-branch",
			AssetID:       asset.ID,
			DefaultBranch: false,
			Slug:          "feature-branch",
			Type:          "branch",
		}
		err := db.Create(&anotherAssetVersion).Error
		assert.NoError(t, err)

		// Create artifacts with same name in different asset versions
		artifact1 := models.Artifact{
			ArtifactName:     "same-name-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		artifact2 := models.Artifact{
			ArtifactName:     "same-name-artifact",
			AssetVersionName: anotherAssetVersion.Name,
			AssetID:          asset.ID,
		}

		err = db.Create(&artifact1).Error
		assert.NoError(t, err)
		err = db.Create(&artifact2).Error
		assert.NoError(t, err)

		// Verify both artifacts exist
		var artifacts []models.Artifact
		err = db.Where("artifact_name = ? AND asset_id = ?", "same-name-artifact", asset.ID).
			Find(&artifacts).Error
		assert.NoError(t, err)
		assert.Len(t, artifacts, 2)

		// Delete only the first artifact
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/artifacts/"+artifact1.ArtifactName, nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx, artifact1)

		err = controller.DeleteArtifact(ctx)

		assert.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)

		// Verify only the first artifact was deleted
		err = db.Where("artifact_name = ? AND asset_id = ?", "same-name-artifact", asset.ID).
			Find(&artifacts).Error
		assert.NoError(t, err)
		assert.Len(t, artifacts, 1)
		assert.Equal(t, anotherAssetVersion.Name, artifacts[0].AssetVersionName)
	})
}
