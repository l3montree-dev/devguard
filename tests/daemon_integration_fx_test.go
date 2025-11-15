// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"os"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
)

// Example of refactored daemon test using FX testbed
func TestDaemonAssetVersionDelete_WithFX(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Set up test data using FX services
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		t.Run("should not delete the asset version if it is the default branch", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")
			assetVersion.DefaultBranch = true
			err := f.DB.Save(&assetVersion).Error
			assert.Nil(t, err)

			// Change updated time to 15 days ago
			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)
			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?",
				changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)

			// Use the injected repositories from FX
			_, err = f.App.AssetVersionRepository.DeleteOldAssetVersions(7)
			assert.Nil(t, err)

			var notDeletedAssetVersion models.AssetVersion
			err = f.DB.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?",
				assetVersion.Name, assetVersion.AssetID).Error

			assert.Nil(t, err) // should find the asset version
			assert.Equal(t, assetVersion.Name, notDeletedAssetVersion.Name)
			assert.Equal(t, assetVersion.AssetID, notDeletedAssetVersion.AssetID)
			assert.Equal(t, assetVersion.DefaultBranch, notDeletedAssetVersion.DefaultBranch)
		})

		t.Run("should delete the asset version", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")

			// Create an artifact using the fixture
			artifact := models.Artifact{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			err := f.DB.Create(&artifact).Error
			assert.Nil(t, err)

			// Create a non-default asset version
			testAssetVersion := f.CreateAssetVersion(asset.ID, "test", false)
			testAssetVersion.LastAccessedAt = time.Now().AddDate(0, 0, -10)
			err = f.DB.Save(&testAssetVersion).Error
			assert.Nil(t, err)

			// Change updated time to 15 days ago
			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)
			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?",
				changeUpdatedTime, testAssetVersion.Name, testAssetVersion.AssetID).Error
			assert.Nil(t, err)

			// Use the injected repository
			_, err = f.App.AssetVersionRepository.DeleteOldAssetVersions(7)
			assert.Nil(t, err)

			var deletedAssetVersion models.AssetVersion
			err = f.DB.First(&deletedAssetVersion, "name = ? AND asset_id = ?",
				testAssetVersion.Name, testAssetVersion.AssetID).Error

			assert.Equal(t, "record not found", err.Error())
		})

		t.Run("should not delete the asset version if it was updated in the last 7 days", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")

			// Create a recently updated asset version
			recentAssetVersion := f.CreateAssetVersion(asset.ID, "recent", false)

			// Use the injected repository
			_, err := f.App.AssetVersionRepository.DeleteOldAssetVersions(7)
			assert.Nil(t, err)

			var notDeletedAssetVersion models.AssetVersion
			err = f.DB.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?",
				recentAssetVersion.Name, recentAssetVersion.AssetID).Error

			assert.Nil(t, err) // should find the asset version
			assert.Equal(t, recentAssetVersion.Name, notDeletedAssetVersion.Name)
		})
	})
}

// Example of a more complex test using multiple FX services
func TestScanWithFXServices(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create test hierarchy
		org := f.CreateOrg("test-org")
		project := f.CreateProject(org.ID, "test-project")
		asset := f.CreateAsset(project.ID, "test-asset")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		t.Run("can access all FX-injected services", func(t *testing.T) {
			// All services are available through the fixture
			assert.NotNil(t, f.App.ScanService)
			assert.NotNil(t, f.App.ComponentService)
			assert.NotNil(t, f.App.DependencyVulnService)
			assert.NotNil(t, f.App.AssetVersionService)

			// Use services directly - no manual construction needed!
			assetVersionFromService, err := f.App.AssetVersionRepository.Read(assetVersion.Name, asset.ID)
			assert.Nil(t, err)
			assert.Equal(t, assetVersion.AssetID, assetVersionFromService.AssetID)
			assert.Equal(t, assetVersion.Name, assetVersionFromService.Name)
		})
	})
}
