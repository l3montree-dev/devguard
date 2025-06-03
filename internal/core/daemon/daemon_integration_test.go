// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
)

func TestDaemonAsssetVersionScan(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.ComponentDependency{},
		&models.Component{},
	)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	_, _, asset := integration_tests.CreateOrgProjectAndAsset(db)
	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       asset.ID,
		DefaultBranch: true,
	}

	assert.Nil(t, assetVersion.Metadata)

	err := db.Create(&assetVersion).Error
	assert.Nil(t, err)

	component := models.Component{
		Purl:                "pkg:npm/react@18.2.0",
		ComponentType:       models.ComponentTypeLibrary,
		Version:             "18.2.0",
		License:             nil,
		Published:           nil,
		ComponentProject:    nil,
		ComponentProjectKey: nil,
	}

	err = db.Create(&component).Error
	assert.Nil(t, err)

	devguardScanner := "github.com/l3montree-dev/devguard/cmd/devguard-scanner" + "/"
	componentDependency := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		AssetVersion:     assetVersion,
		ScannerID:        devguardScanner + "sca",
		ComponentPurl:    nil,
		DependencyPurl:   "pkg:npm/react-dom@18.2.0",
		Dependency:       component,
	}

	err = db.Create(&componentDependency).Error
	assert.Nil(t, err)

	t.Run("should update the last scan time of the asset version", func(t *testing.T) {

		casbinRBACProvider := mocks.NewRBACProvider(t)

		err = daemon.ScanAssetVersions(db, casbinRBACProvider)
		assert.Nil(t, err)

		//get assetversion from db to check if it was updated
		var updatedAssetVersion models.AssetVersion
		err = db.First(&updatedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)
		assert.NotNil(t, updatedAssetVersion.Metadata)
		assert.Contains(t, updatedAssetVersion.Metadata, "sca")

		metadataMap := updatedAssetVersion.Metadata["sca"]
		metadataBytes, err := json.Marshal(metadataMap)
		assert.Nil(t, err)
		var metadata models.ScannerInformation
		err = json.Unmarshal(metadataBytes, &metadata)
		assert.Nil(t, err)

		assert.WithinDuration(t, time.Now(), *metadata.LastScan, time.Hour)

	})

}
