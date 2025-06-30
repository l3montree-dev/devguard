// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestDaemonAsssetVersionScan(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	err := db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.ComponentDependency{},
		&models.Component{},
		&models.CVE{},
		&models.AffectedComponent{},
		&models.DependencyVuln{},
		&models.Exploit{},
	)
	assert.Nil(t, err)

	casbinRBACProvider := mocks.NewRBACProvider(t)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	_, _, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	t.Run("should update the last scan time of the asset version", func(t *testing.T) {

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

		devguardScanner := "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca"
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			AssetVersion:     assetVersion,
			ScannerIDs:       devguardScanner,
			ComponentPurl:    nil,
			DependencyPurl:   "pkg:npm/react@18.2.0",
			Dependency:       models.Component{Purl: "pkg:npm/react@18.2.0"},
		}

		err = db.Create(&componentDependency).Error
		assert.Nil(t, err)

		err = daemon.ScanAssetVersions(db, casbinRBACProvider)
		assert.Nil(t, err)

		//get assetversion from db to check if it was updated
		var updatedAssetVersion models.AssetVersion
		err = db.First(&updatedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)
		assert.NotNil(t, updatedAssetVersion.Metadata)
		assert.Contains(t, updatedAssetVersion.Metadata, devguardScanner)

		metadataMap := updatedAssetVersion.Metadata[devguardScanner]
		metadataBytes, err := json.Marshal(metadataMap)
		assert.Nil(t, err)
		var metadata models.ScannerInformation
		err = json.Unmarshal(metadataBytes, &metadata)
		assert.Nil(t, err)

		assert.WithinDuration(t, time.Now(), *metadata.LastScan, time.Minute)
	})

	t.Run("should find the cve in the component dependency", func(t *testing.T) {

		affectedComponent := models.AffectedComponent{
			ID:                 "1",
			PurlWithoutVersion: "pkg:npm/react",
			Version:            utils.Ptr("18.2.0"),
			CVE:                []models.CVE{{CVE: "CVE-2025-46569"}},
		}

		err = db.Create(&affectedComponent).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
			AffectedComponents: []*models.AffectedComponent{{
				ID: "1",
			}},
		}
		err = db.Save(&cve).Error
		assert.Nil(t, err)

		err = daemon.ScanAssetVersions(db, casbinRBACProvider)
		assert.Nil(t, err)

		var dependencyVuln []models.DependencyVuln

		err := db.Preload("CVE").Find(&dependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)
		assert.Len(t, dependencyVuln, 1)
		assert.Equal(t, "CVE-2025-46569", dependencyVuln[0].CVE.CVE)
	})
}

func TestDaemonSyncTickets(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	err := db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.CVE{},
		&models.Exploit{},
		&models.VulnEvent{},
		&models.DependencyVuln{},
		&models.GitLabIntegration{},
	)
	assert.Nil(t, err)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	org.Slug = "org-slug"
	err = db.Save(&org).Error
	assert.Nil(t, err)
	project.Slug = "project-slug"
	err = db.Save(&project).Error
	assert.Nil(t, err)

	repoID := "gitlab:7c95b7f6-a921-4b27-91ac-38cb94877324:456"
	asset.RepositoryID = &repoID
	cvssThreshold := 7.0
	asset.CVSSAutomaticTicketThreshold = &cvssThreshold
	err = db.Save(&asset).Error
	assert.Nil(t, err)

	cve := models.CVE{
		CVE:  "CVE-2025-46569",
		CVSS: 8.0,
	}
	err = db.Save(&cve).Error
	assert.Nil(t, err)

	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			AssetVersionName: assetVersion.Name,
			TicketID:         nil,
			TicketURL:        nil,
			ScannerIDs:       "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca",
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},
		CVE:               &cve,
		CVEID:             utils.Ptr(cve.CVE),
		ComponentDepth:    utils.Ptr(1),
		RawRiskAssessment: utils.Ptr(8.0),
	}
	err = db.Create(&dependencyVuln).Error
	assert.Nil(t, err)

	assert.Nil(t, dependencyVuln.TicketID)
	assert.Nil(t, dependencyVuln.TicketURL)

	clientfactory, gitlabClientFacade := integration_tests.NewTestClientFactory(t)
	gitlabIntegration := gitlabint.NewGitlabIntegration(
		db,
		gitlabint.NewGitLabOauth2Integrations(db),
		mocks.NewRBACProvider(t),
		clientfactory,
	)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabIntegration)

	gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(
		&gitlab.Issue{
			ID: 12345,
		}, nil, nil)

	gitlabClientFacade.On("CreateIssueComment", mock.Anything, 456, 0, &gitlab.CreateIssueNoteOptions{
		Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
	}).Return(nil, nil, nil)

	err = daemon.SyncTickets(db, thirdPartyIntegration)
	assert.Nil(t, err)

	db.Find(&dependencyVuln, "id = ?", dependencyVuln.ID)

	t.Run("should create a ticket if the CVSS if above the threshold", func(t *testing.T) {

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.TicketID)
		assert.NotNil(t, updatedDependencyVuln.TicketURL)
	})

	t.Run("should not close the ticket if the CVSS is below the threshold but the ticket was manually created", func(t *testing.T) {
		gitlabClientFacade.ExpectedCalls = nil
		gitlabClientFacade.Calls = nil
		// Update the CVSS threshold to a value below the current CVSS
		newCvssThreshold := 9.0
		asset.CVSSAutomaticTicketThreshold = &newCvssThreshold
		err = db.Save(&asset).Error
		assert.Nil(t, err)

		dependencyVuln.ManualTicketCreation = true
		err = db.Save(&dependencyVuln).Error
		assert.Nil(t, err)

		gitlabClientFacade.On("EditIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&gitlab.Issue{
				ID:    12345,
				State: "opened",
			}, nil, nil)

		err = daemon.SyncTickets(db, thirdPartyIntegration)
		assert.Nil(t, err)

		// Check if the ticket was updated
		editedIssueOptions := gitlabClientFacade.Calls[0].Arguments[3].(*gitlab.UpdateIssueOptions)
		assert.Equal(t, "reopen", *editedIssueOptions.StateEvent)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.TicketID)
		assert.NotNil(t, updatedDependencyVuln.TicketURL)
	})

	t.Run("should close the ticket if the CVSS is below the threshold", func(t *testing.T) {
		gitlabClientFacade.ExpectedCalls = nil
		gitlabClientFacade.Calls = nil

		// Update the CVSS threshold to a value below the current CVSS
		newCvssThreshold := 9.0
		asset.CVSSAutomaticTicketThreshold = &newCvssThreshold
		err = db.Save(&asset).Error
		assert.Nil(t, err)

		dependencyVuln.ManualTicketCreation = false
		err = db.Save(&dependencyVuln).Error
		assert.Nil(t, err)

		gitlabClientFacade.On("EditIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			&gitlab.Issue{
				ID:    12345,
				State: "closed",
			}, nil, nil)

		err = daemon.SyncTickets(db, thirdPartyIntegration)
		assert.Nil(t, err)

		// Check if the ticket was updated
		editedIssueOptions := gitlabClientFacade.Calls[0].Arguments[3].(*gitlab.UpdateIssueOptions)

		assert.Equal(t, "close", *editedIssueOptions.StateEvent)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.TicketID)
		assert.NotNil(t, updatedDependencyVuln.TicketURL)
	})

}

func TestDaemonRecalculateRisk(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	err := db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.ComponentDependency{},
		&models.Component{},
		&models.CVE{},
		&models.Exploit{},
		&models.VulnEvent{},
		&models.AffectedComponent{},
		&models.DependencyVuln{},
	)
	assert.Nil(t, err)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	org.Slug = "org-slug"
	err = db.Save(&org).Error
	assert.Nil(t, err)
	project.Slug = "project-slug"
	err = db.Save(&project).Error
	assert.Nil(t, err)

	asset.AvailabilityRequirement = models.RequirementLevelLow
	asset.ConfidentialityRequirement = models.RequirementLevelLow
	asset.IntegrityRequirement = models.RequirementLevelLow
	err = db.Save(&asset).Error
	assert.Nil(t, err)

	cve := models.CVE{
		CVE:  "CVE-2025-46569",
		CVSS: 8.0,

		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
	}
	err = db.Save(&cve).Error
	assert.Nil(t, err)

	oldRawRiskValue := 1.0
	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			AssetVersionName: assetVersion.Name,
			ScannerIDs:       "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca",
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},
		CVE:               &cve,
		CVEID:             utils.Ptr(cve.CVE),
		ComponentDepth:    utils.Ptr(1),
		RawRiskAssessment: utils.Ptr(oldRawRiskValue),
	}
	err = db.Create(&dependencyVuln).Error
	assert.Nil(t, err)

	//gitlabClientFacade
	clientfactory, _ := integration_tests.NewTestClientFactory(t)
	gitlabIntegration := gitlabint.NewGitlabIntegration(
		db,
		gitlabint.NewGitLabOauth2Integrations(db),
		mocks.NewRBACProvider(t),
		clientfactory,
	)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabIntegration)

	t.Run("should recalculate the risk of the dependency vuln", func(t *testing.T) {
		err = daemon.RecalculateRisk(db, thirdPartyIntegration)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.RawRiskAssessment)
		assert.NotEqual(t, oldRawRiskValue, *updatedDependencyVuln.RawRiskAssessment)
	})

	t.Run("should recalculate the risk of the dependency vuln to higher value if the requirements are set to high", func(t *testing.T) {
		asset.AvailabilityRequirement = models.RequirementLevelHigh
		asset.ConfidentialityRequirement = models.RequirementLevelHigh
		asset.IntegrityRequirement = models.RequirementLevelHigh
		err = db.Save(&asset).Error
		assert.Nil(t, err)

		err = db.First(&dependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)
		oldRawRiskValue = *dependencyVuln.RawRiskAssessment

		err = daemon.RecalculateRisk(db, thirdPartyIntegration)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.RawRiskAssessment)
		assert.Greater(t, *updatedDependencyVuln.RawRiskAssessment, oldRawRiskValue)
	})
}

func TestDaemonComponentProperties(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	err := db.AutoMigrate(
		&models.Org{},
		&models.Project{},
		&models.AssetVersion{},
		&models.Asset{},
		&models.ComponentDependency{},
		&models.Component{},
		&models.CVE{},
		&models.AffectedComponent{},
		&models.DependencyVuln{},
		&models.Exploit{},
	)
	assert.Nil(t, err)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	org.Slug = "org-slug"
	err = db.Save(&org).Error
	assert.Nil(t, err)
	project.Slug = "project-slug"
	err = db.Save(&project).Error
	assert.Nil(t, err)

	componentA := models.Component{
		Purl:          "pkg:npm/react@18.2.0",
		ComponentType: models.ComponentTypeLibrary,
		Version:       "18.2.0",
	}
	err = db.Create(&componentA).Error
	assert.Nil(t, err)

	componentB := models.Component{
		Purl:          "pkg:npm/react-dom@15.0.0",
		ComponentType: models.ComponentTypeLibrary,
		Version:       "15.0.0",
	}
	err = db.Create(&componentB).Error
	assert.Nil(t, err)
	devguardScanner := "github.com/l3montree-dev/devguard/cmd/devguard-scanner" + "/"
	componentDependencyA := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		AssetVersion:     assetVersion,
		ScannerIDs:       devguardScanner + "sca",
		ComponentPurl:    nil,
		DependencyPurl:   "pkg:npm/react@18.2.0",
		Dependency:       componentA,
	}
	err = db.Create(&componentDependencyA).Error
	assert.Nil(t, err)
	componentDependencyB := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		AssetVersion:     assetVersion,
		ScannerIDs:       devguardScanner + "sca",
		ComponentPurl:    &componentA.Purl,
		DependencyPurl:   "pkg:npm/react-dom@15.0.0",
		Dependency:       componentB,
	}
	err = db.Create(&componentDependencyB).Error
	assert.Nil(t, err)

	affectedComponent := models.AffectedComponent{
		ID:                 "1",
		PurlWithoutVersion: "pkg:npm/react-dom",
		Version:            utils.Ptr("15.0.0"),
		CVE:                []models.CVE{{CVE: "CVE-2025-46569"}},
	}
	err = db.Create(&affectedComponent).Error
	assert.Nil(t, err)

	cve := models.CVE{
		CVE:  "CVE-2025-46569",
		CVSS: 8.0,
		AffectedComponents: []*models.AffectedComponent{{
			ID: "1",
		}},
	}
	err = db.Save(&cve).Error
	assert.Nil(t, err)

	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "1",
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			AssetVersionName: assetVersion.Name,
			ScannerIDs:       "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca",
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},

		CVE:               &cve,
		CVEID:             utils.Ptr(cve.CVE),
		ComponentDepth:    utils.Ptr(3), //this is a wrong value, it should be updated by the daemon
		ComponentPurl:     utils.Ptr("pkg:npm/react-dom@15.0.0"),
		RawRiskAssessment: utils.Ptr(8.0),
	}
	err = db.Create(&dependencyVuln).Error
	assert.Nil(t, err)
	assert.Nil(t, dependencyVuln.ComponentFixedVersion)

	t.Run("should update the component properties, including fixed version and component depth", func(t *testing.T) {
		fixedVersion := "15.0.1"
		dependencyVuln.ComponentFixedVersion = &fixedVersion
		err = db.Save(&dependencyVuln).Error
		assert.Nil(t, err)

		err = daemon.UpdateComponentProperties(db)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.ComponentFixedVersion)
		assert.Equal(t, fixedVersion, *updatedDependencyVuln.ComponentFixedVersion)
		//componentB is the affected component
		//componentA -> componentB
		assert.Equal(t, 1, *updatedDependencyVuln.ComponentDepth)

	})

	t.Run("should update the component depth to a lower value, if a component dependency is found with a shorter path, and the scanner is only container-scanning or sca", func(t *testing.T) {
		componentDependencyC := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			AssetVersion:     assetVersion,
			ScannerIDs:       devguardScanner + "sca",
			ComponentPurl:    nil,
			DependencyPurl:   "pkg:npm/react-dom@15.0.0",
			Dependency:       componentB,
		}
		err = db.Create(&componentDependencyC).Error
		assert.Nil(t, err)

		err = daemon.UpdateComponentProperties(db)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.ComponentDepth)
		assert.Equal(t, 0, *updatedDependencyVuln.ComponentDepth)

		//delete the component dependency
		err = db.Delete(&componentDependencyC).Error
		assert.Nil(t, err)

		err = daemon.UpdateComponentProperties(db)
		assert.Nil(t, err)
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.ComponentDepth)
		assert.Equal(t, 1, *updatedDependencyVuln.ComponentDepth)

	})

	t.Run("should not update the component depth to shorter value, if a new component dependency has a shorter path but the container-scanning scanner is used additionally to the sca scanner", func(t *testing.T) {

		dependencyVuln.ScannerIDs = "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning"
		err = db.Save(&dependencyVuln).Error
		assert.Nil(t, err)

		componentDependencyC := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			AssetVersion:     assetVersion,
			ScannerIDs:       devguardScanner + "container-scanning",
			ComponentPurl:    nil,
			DependencyPurl:   "pkg:npm/react-dom@15.0.0",
			Dependency:       componentB,
		}
		err = db.Create(&componentDependencyC).Error
		assert.Nil(t, err)

		err = daemon.UpdateComponentProperties(db)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.ComponentDepth)
		assert.Equal(t, 1, *updatedDependencyVuln.ComponentDepth)

		//delete the component dependency
		err = db.Delete(&componentDependencyC).Error
		assert.Nil(t, err)

	})

	t.Run("should update the component depth to lower value, if a new component dependency has a shorter path and the container-scanning scanner is the only scanner used", func(t *testing.T) {

		dependencyVuln.ScannerIDs = "github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning"
		err = db.Save(&dependencyVuln).Error
		assert.Nil(t, err)

		componentDependencyC := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			AssetVersion:     assetVersion,
			ScannerIDs:       devguardScanner + "container-scanning",
			ComponentPurl:    nil,
			DependencyPurl:   "pkg:npm/react-dom@15.0.0",
			Dependency:       componentB,
		}
		err = db.Create(&componentDependencyC).Error
		assert.Nil(t, err)

		err = daemon.UpdateComponentProperties(db)
		assert.Nil(t, err)

		var updatedDependencyVuln models.DependencyVuln
		err = db.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)

		assert.NotNil(t, updatedDependencyVuln.ComponentDepth)
		assert.Equal(t, 0, *updatedDependencyVuln.ComponentDepth)

	})

}
