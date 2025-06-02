// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
)

func TestDaemon(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
	)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	_, _, asset := integration_tests.CreateOrgProjectAndAsset(db)

	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       asset.ID,
		DefaultBranch: true,
	}

	fmt.Println("asset version metadata:", assetVersion.Metadata)

	err := db.Create(&assetVersion).Error
	assert.Nil(t, err)

	t.Run("Initialize HTTP Controller", func(t *testing.T) {

		casbinRBACProvider := mocks.NewRBACProvider(t)

		err = daemon.ScanAssetVersions(db, casbinRBACProvider)
		assert.Nil(t, err)

		fmt.Println("asset version metadata:", assetVersion.Metadata)

	})
}
