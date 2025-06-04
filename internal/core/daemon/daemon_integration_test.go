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
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestDaemonSyncTickets(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.CVE{},
		&models.Exploit{},
		&models.VulnEvent{},
		&models.DependencyVuln{},
	)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	org, project, asset := integration_tests.CreateOrgProjectAndAsset(db)

	org.Slug = "org-slug"
	err := db.Save(&org).Error
	project.Slug = "project-slug"
	err = db.Save(&project).Error

	repoID := "repo-123"
	asset.RepositoryID = &repoID
	cvssThreshold := 7.0
	asset.CVSSAutomaticTicketThreshold = &cvssThreshold
	err = db.Save(&asset).Error

	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       asset.ID,
		DefaultBranch: true,
	}
	err = db.Create(&assetVersion).Error
	assert.Nil(t, err)

	cve := models.CVE{
		CVE:  "CVE-2025-46569",
		CVSS: 8.0,
	}
	err = db.Save(&cve).Error

	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetID:              asset.ID,
			AssetVersion:         assetVersion,
			AssetVersionName:     assetVersion.Name,
			ManualTicketCreation: true,
			TicketID:             nil,
			TicketURL:            nil,
			ScannerIDs:           "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca",
			State:                models.VulnStateOpen,
			LastDetected:         time.Now(),
		},
		CVE:   &cve,
		CVEID: utils.Ptr(cve.CVE),
	}
	err = db.Create(&dependencyVuln).Error
	assert.Nil(t, err)

	assert.Nil(t, dependencyVuln.TicketID)
	assert.Nil(t, dependencyVuln.TicketURL)

	casbinRBACProvider := mocks.NewRBACProvider(t)
	thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
	thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, "main", "repo-123", mock.Anything, project.Slug, org.Slug, "Risk exceeds predefined threshold", "system").Return(nil).Once()

	t.Run("should  create a ticket if the CVSS if above the threshold", func(t *testing.T) {

		err = daemon.SyncTickets(db, casbinRBACProvider, thirdPartyIntegration)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.TicketID)
		assert.NotNil(t, updatedDependencyVuln.TicketURL)

	})

}
