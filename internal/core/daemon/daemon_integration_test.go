// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon_test

import (
	"fmt"
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

func TestDaemonAssetVersionDelete(t *testing.T) {
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
		&models.VulnEvent{},
		&models.FirstPartyVuln{},
		&models.Artifact{},
	)
	assert.Nil(t, err)

	_, _, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	t.Run("should not delete the asset version if it is the default branch", func(t *testing.T) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")
		assetVersion.DefaultBranch = true
		err = db.Save(&assetVersion).Error
		assert.Nil(t, err)

		changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)

		err = db.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)

		err = daemon.DeleteOldAssetVersions(db)
		assert.Nil(t, err)

		var notDeletedAssetVersion models.AssetVersion
		err = db.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error

		assert.Nil(t, err) // should find the asset version

		assert.Equal(t, assetVersion.Name, notDeletedAssetVersion.Name)
		assert.Equal(t, assetVersion.AssetID, notDeletedAssetVersion.AssetID)
		assert.Equal(t, assetVersion.DefaultBranch, notDeletedAssetVersion.DefaultBranch)

	})

	t.Run("should delete the asset version", func(t *testing.T) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		artifact := models.Artifact{ArtifactName: "artifact1",
			AssetVersionName: assetVersion.Name, AssetID: asset.ID}

		err = db.Create(&artifact).Error
		assert.Nil(t, err)

		assetVersion := models.AssetVersion{
			Name:          "test",
			AssetID:       asset.ID,
			DefaultBranch: false,
			Slug:          "main",
			Type:          "branch",
		}
		err = db.Create(&assetVersion).Error
		assert.Nil(t, err)

		changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)

		err = db.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)

		err = daemon.DeleteOldAssetVersions(db)
		assert.Nil(t, err)

		var deletedAssetVersion models.AssetVersion
		err = db.First(&deletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error

		assert.Equal(t, "record not found", err.Error())

	})

	t.Run("should not delete the asset version if it was updated in the last 7 days", func(t *testing.T) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		assetVersion := models.AssetVersion{
			Name:          "test",
			AssetID:       asset.ID,
			DefaultBranch: false,
			Slug:          "main",
			Type:          "branch",
		}
		err = db.Create(&assetVersion).Error
		assert.Nil(t, err)

		changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 6) // Set the updated at time to 6 days ago

		assetVersion.UpdatedAt = changeUpdatedTime

		err = db.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)

		err = daemon.DeleteOldAssetVersions(db)
		assert.Nil(t, err)

		var notDeletedAssetVersion models.AssetVersion
		err = db.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)

	})

	t.Run("should delete the asset version with all related data", func(t *testing.T) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		assetVersion := models.AssetVersion{
			Name:          "test-dependency",
			AssetID:       asset.ID,
			DefaultBranch: false,
			Slug:          "main",
			Type:          "branch",
		}
		err = db.Create(&assetVersion).Error
		assert.Nil(t, err)

		vulnID := "vuln-1"

		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			Artifacts: []models.Artifact{{ArtifactName: "artifact1",
				AssetVersionName: assetVersion.Name, AssetID: asset.ID}},
			ComponentPurl:  nil,
			DependencyPurl: "pkg:npm/react@18.2.0",
			Dependency:     models.Component{Purl: "pkg:npm/react@18.2.0"},
		}

		err = db.Create(&componentDependency).Error
		assert.Nil(t, err)

		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				ID:               vulnID,
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
			},
			Artifacts: []models.Artifact{{ArtifactName: "artifact1", AssetVersionName: assetVersion.Name, AssetID: asset.ID}},
		}

		err = db.Create(&dependencyVuln).Error
		assert.Nil(t, err)

		firstPartyVuln := models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				ID:               vulnID,
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
			},
		}

		err = db.Create(&firstPartyVuln).Error
		assert.Nil(t, err)

		vulnEvent := models.VulnEvent{
			VulnID: dependencyVuln.ID,
		}

		err = db.Create(&vulnEvent).Error
		assert.Nil(t, err)

		changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15) // Set the updated at time to 8 days ago
		err = db.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)

		updaedAssetVersion := models.AssetVersion{}
		err = db.First(&updaedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
		assert.Nil(t, err)
		fmt.Println("Updated Asset Version:", updaedAssetVersion.UpdatedAt)

		err = daemon.DeleteOldAssetVersions(db)
		assert.Nil(t, err)

		var deletedAssetVersion models.AssetVersion
		err = db.First(&deletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
		assert.Equal(t, "record not found", err.Error())

		var deletedComponentDependency models.ComponentDependency
		err = db.First(&deletedComponentDependency, "asset_id = ? AND asset_version_name = ?", componentDependency.AssetID, componentDependency.AssetVersionName).Error
		assert.Equal(t, "record not found", err.Error())

		var deletedDependencyVuln models.DependencyVuln
		err = db.First(&deletedDependencyVuln, "asset_id = ? AND asset_version_name = ?", dependencyVuln.AssetID, dependencyVuln.AssetVersionName).Error
		assert.Equal(t, "record not found", err.Error())

		var deletedFirstPartyVuln models.FirstPartyVuln
		err = db.First(&deletedFirstPartyVuln, "asset_id = ? AND asset_version_name = ?", firstPartyVuln.AssetID, firstPartyVuln.AssetVersionName).Error
		assert.Equal(t, "record not found", err.Error())

		var deletedVulnEvent models.VulnEvent
		err = db.First(&deletedVulnEvent, "vuln_id = ?", vulnEvent.VulnID).Error
		fmt.Println("Deleted Vuln Event:", deletedVulnEvent.ID)
		assert.Equal(t, "record not found", err.Error())

	})

}

func TestDaemonAsssetVersionScan(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	casbinRBACProvider := mocks.NewRBACProvider(t)

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	_, _, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	t.Run("should find the cve in the component dependency", func(t *testing.T) {

		affectedComponent := models.AffectedComponent{
			ID:                 "1",
			PurlWithoutVersion: "pkg:npm/react",
			Version:            utils.Ptr("18.2.0"),
			CVE:                []models.CVE{{CVE: "CVE-2025-46569"}},
		}

		// create the component
		component := models.Component{
			Purl: "pkg:npm/react@18.2.0",
		}
		assert.Nil(t, db.Create(&component).Error)

		err := db.Create(&affectedComponent).Error
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

		// create the artifact
		artifact := models.Artifact{ArtifactName: "artifact1",
			AssetVersionName: assetVersion.Name, AssetID: asset.ID}
		assert.Nil(t, db.Create(&artifact).Error)

		// create a component dependency between the artifact and the affected component
		componentDependency := models.ComponentDependency{
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
			Artifacts: []models.Artifact{
				artifact,
			},
			ComponentPurl:  nil,
			DependencyPurl: "pkg:npm/react@18.2.0",
		}
		err = db.Create(&componentDependency).Error
		assert.Nil(t, err)

		err = daemon.ScanArtifacts(db, casbinRBACProvider)
		assert.Nil(t, err)

		var dependencyVuln []models.DependencyVuln

		err = db.Preload("CVE").Find(&dependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
		assert.Nil(t, err)
		assert.Len(t, dependencyVuln, 1)
		assert.Equal(t, "CVE-2025-46569", dependencyVuln[0].CVE.CVE)
	})
}

func TestDaemonSyncTickets(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	org.Slug = "org-slug"
	err := db.Save(&org).Error
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
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},
		Artifacts:         []models.Artifact{{ArtifactName: "artifact1", AssetVersionName: assetVersion.Name, AssetID: asset.ID}},
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
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},
		Artifacts:         []models.Artifact{{ArtifactName: "artifact1", AssetVersionName: assetVersion.Name, AssetID: asset.ID}},
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
		&models.Artifact{},
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
	artifactA := models.Artifact{ArtifactName: "sca", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	componentDependencyA := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		Artifacts:        []models.Artifact{artifactA},
		ComponentPurl:    nil,
		DependencyPurl:   "pkg:npm/react@18.2.0",
		Dependency:       componentA,
	}
	err = db.Create(&componentDependencyA).Error
	assert.Nil(t, err)
	artifactB := models.Artifact{ArtifactName: "sca", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	componentDependencyB := models.ComponentDependency{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		Artifacts:        []models.Artifact{artifactB},
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

	artifact := models.Artifact{ArtifactName: "sca", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	dependencyVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "1",
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			AssetVersionName: assetVersion.Name,
			State:            models.VulnStateOpen,
			LastDetected:     time.Now(),
		},

		CVE:               &cve,
		CVEID:             utils.Ptr(cve.CVE),
		ComponentDepth:    utils.Ptr(3), //this is a wrong value, it should be updated by the daemon
		ComponentPurl:     utils.Ptr("pkg:npm/react-dom@15.0.0"),
		RawRiskAssessment: utils.Ptr(8.0),
		Artifacts:         []models.Artifact{artifact},
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

}
