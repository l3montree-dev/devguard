// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestDeleteArtifactIntegration(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create test organization, project, asset, and asset version using FX helper
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// Setup echo app
		app := echo.New()

		// Setup context helper
		setupContext := func(ctx shared.Context, artifactToDelete models.Artifact) {
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetAssetVersion(ctx, assetVersion)
			shared.SetArtifact(ctx, artifactToDelete)
		}

		t.Run("should successfully delete an existing artifact", func(t *testing.T) {
			// Create a test artifact
			testArtifact := models.Artifact{
				ArtifactName:     "test-artifact-delete",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			err := f.DB.Create(&testArtifact).Error
			assert.NoError(t, err)

			// Verify artifact exists before deletion
			var existingArtifact models.Artifact
			err = f.DB.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
				testArtifact.ArtifactName, testArtifact.AssetVersionName, testArtifact.AssetID).
				First(&existingArtifact).Error
			assert.NoError(t, err)
			assert.Equal(t, testArtifact.ArtifactName, existingArtifact.ArtifactName)

			// Setup HTTP request and response
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("DELETE", "/artifacts/"+testArtifact.ArtifactName, nil)
			ctx := app.NewContext(req, recorder)
			setupContext(ctx, testArtifact)

			// Execute the delete operation using FX-injected controller
			err = f.App.ArtifactController.DeleteArtifact(ctx)

			// Verify the operation succeeded
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Verify artifact was actually deleted from database
			var deletedArtifact models.Artifact
			err = f.DB.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
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
			err := f.DB.Create(&testArtifact).Error
			assert.NoError(t, err)

			// Create a component that might be associated with this artifact
			testComponent := models.Component{
				Purl:    "pkg:npm/test-component@1.0.0",
				Version: "1.0.0",
			}
			err = f.DB.Create(&testComponent).Error
			assert.NoError(t, err)

			// Create a CVE record first (required by foreign key constraint)
			testCVE := models.CVE{
				CVE:         "CVE-2024-12345",
				Description: "Test CVE for integration testing",
				CVSS:        7.5,
			}
			err = f.DB.Create(&testCVE).Error
			assert.NoError(t, err)

			// Create a dependency vulnerability with the artifact association atomically
			// This prevents race condition with cleanup goroutines from other tests
			testDepVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
					State:            dtos.VulnStateOpen,
				},
				CVEID:         &testCVE.CVE,
				ComponentPurl: &testComponent.Purl,
				Artifacts:     []models.Artifact{testArtifact}, // Associate artifact immediately
			}
			err = f.DB.Create(&testDepVuln).Error
			assert.NoError(t, err)

			// Verify association exists before deletion
			artifactCount := f.DB.Model(&testDepVuln).Association("Artifacts").Count()
			assert.Equal(t, int64(1), artifactCount) // Setup HTTP request and response
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("DELETE", "/artifacts/"+testArtifact.ArtifactName, nil)
			ctx := app.NewContext(req, recorder)
			setupContext(ctx, testArtifact)

			// Execute the delete operation
			err = f.App.ArtifactController.DeleteArtifact(ctx)

			// Verify the operation succeeded
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Verify artifact was deleted
			var deletedArtifact models.Artifact
			err = f.DB.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
				testArtifact.ArtifactName, testArtifact.AssetVersionName, testArtifact.AssetID).
				First(&deletedArtifact).Error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "record not found")

			// Verify artifact associations were cleaned up (many-to-many table should be cleaned up automatically)
			artifactCountAfter := f.DB.Model(&testDepVuln).Association("Artifacts").Count()
			assert.Equal(t, int64(0), artifactCountAfter) // Association should be gone due to CASCADE delete
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
			err := f.App.ArtifactController.DeleteArtifact(ctx)

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
			err := f.DB.Create(&anotherAssetVersion).Error
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

			err = f.DB.Create(&artifact1).Error
			assert.NoError(t, err)
			err = f.DB.Create(&artifact2).Error
			assert.NoError(t, err)

			// Verify both artifacts exist
			var artifacts []models.Artifact
			err = f.DB.Where("artifact_name = ? AND asset_id = ?", "same-name-artifact", asset.ID).
				Find(&artifacts).Error
			assert.NoError(t, err)
			assert.Len(t, artifacts, 2)

			// Delete only the first artifact
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("DELETE", "/artifacts/"+artifact1.ArtifactName, nil)
			ctx := app.NewContext(req, recorder)
			setupContext(ctx, artifact1)

			err = f.App.ArtifactController.DeleteArtifact(ctx)

			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Verify only the first artifact was deleted
			err = f.DB.Where("artifact_name = ? AND asset_id = ?", "same-name-artifact", asset.ID).
				Find(&artifacts).Error
			assert.NoError(t, err)
			assert.Len(t, artifacts, 1)
			assert.Equal(t, anotherAssetVersion.Name, artifacts[0].AssetVersionName)
		})
	})
}
