// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"go.uber.org/fx"
)

func TestDaemonAssetVersionDelete(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		var err error

		t.Run("should not delete the asset version if it is the default branch", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")
			assetVersion.DefaultBranch = true
			err = f.DB.Save(&assetVersion).Error
			assert.Nil(t, err)

			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)

			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)

			err = daemons.DeleteOldAssetVersions(f.App.AssetVersionRepository, f.App.VulnEventRepository)
			assert.Nil(t, err)

			var notDeletedAssetVersion models.AssetVersion
			err = f.DB.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error

			assert.Nil(t, err) // should find the asset version

			assert.Equal(t, assetVersion.Name, notDeletedAssetVersion.Name)
			assert.Equal(t, assetVersion.AssetID, notDeletedAssetVersion.AssetID)
			assert.Equal(t, assetVersion.DefaultBranch, notDeletedAssetVersion.DefaultBranch)
		})

		t.Run("should delete the asset version", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")

			artifact := models.Artifact{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}

			err = f.DB.Create(&artifact).Error
			assert.Nil(t, err)

			assetVersion := models.AssetVersion{
				Name:           "test",
				AssetID:        asset.ID,
				DefaultBranch:  false,
				Slug:           "main",
				Type:           "branch",
				LastAccessedAt: time.Now().AddDate(0, 0, -10), // Set last accessed to 10 days ago
			}
			err = f.DB.Create(&assetVersion).Error
			assert.Nil(t, err)

			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15)

			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)

			err = daemons.DeleteOldAssetVersions(f.App.AssetVersionRepository, f.App.VulnEventRepository)
			assert.Nil(t, err)

			var deletedAssetVersion models.AssetVersion
			err = f.DB.First(&deletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error

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
			err = f.DB.Create(&assetVersion).Error
			assert.Nil(t, err)

			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 6) // Set the updated at time to 6 days ago

			assetVersion.UpdatedAt = changeUpdatedTime

			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)

			err = daemons.DeleteOldAssetVersions(f.App.AssetVersionRepository, f.App.VulnEventRepository)
			assert.Nil(t, err)

			var notDeletedAssetVersion models.AssetVersion
			err = f.DB.First(&notDeletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)
		})

		t.Run("should delete the asset version with all related data", func(t *testing.T) {
			os.Setenv("FRONTEND_URL", "FRONTEND_URL")

			assetVersion := models.AssetVersion{
				Name:           "test-dependency",
				AssetID:        asset.ID,
				DefaultBranch:  false,
				Slug:           "main",
				Type:           "branch",
				LastAccessedAt: time.Now().AddDate(0, 0, -10), // Set last accessed to 10 days ago
			}
			err = f.DB.Create(&assetVersion).Error
			assert.Nil(t, err)

			vulnID := "vuln-1"

			componentDependency := models.ComponentDependency{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				Artifacts: []models.Artifact{{
					ArtifactName:     "artifact1",
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
				}},
				ComponentPurl:  nil,
				DependencyPurl: "pkg:npm/react@18.2.0",
				Dependency:     models.Component{Purl: "pkg:npm/react@18.2.0"},
			}

			err = f.DB.Create(&componentDependency).Error
			assert.Nil(t, err)

			dependencyVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					ID:               vulnID,
					AssetID:          asset.ID,
					AssetVersion:     assetVersion,
					AssetVersionName: assetVersion.Name,
				},
				Artifacts: []models.Artifact{{
					ArtifactName:     "artifact1",
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
				}},
			}

			err = f.DB.Create(&dependencyVuln).Error
			assert.Nil(t, err)

			firstPartyVuln := models.FirstPartyVuln{
				Vulnerability: models.Vulnerability{
					ID:               vulnID,
					AssetID:          asset.ID,
					AssetVersion:     assetVersion,
					AssetVersionName: assetVersion.Name,
				},
			}

			err = f.DB.Create(&firstPartyVuln).Error
			assert.Nil(t, err)

			vulnEvent := models.VulnEvent{
				VulnID: dependencyVuln.ID,
			}

			err = f.DB.Create(&vulnEvent).Error
			assert.Nil(t, err)

			changeUpdatedTime := time.Now().Add(-time.Hour * 24 * 15) // Set the updated at time to 8 days ago
			err = f.DB.Exec("UPDATE asset_versions SET updated_at = ? WHERE name = ? AND asset_id = ?", changeUpdatedTime, assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)

			updaedAssetVersion := models.AssetVersion{}
			err = f.DB.First(&updaedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
			assert.Nil(t, err)
			fmt.Println("Updated Asset Version:", updaedAssetVersion.UpdatedAt)

			err = daemons.DeleteOldAssetVersions(f.App.AssetVersionRepository, f.App.VulnEventRepository)
			assert.Nil(t, err)

			var deletedAssetVersion models.AssetVersion
			err = f.DB.First(&deletedAssetVersion, "name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Error
			assert.Equal(t, "record not found", err.Error())

			var deletedComponentDependency models.ComponentDependency
			err = f.DB.First(&deletedComponentDependency, "asset_id = ? AND asset_version_name = ?", componentDependency.AssetID, componentDependency.AssetVersionName).Error
			assert.Equal(t, "record not found", err.Error())

			var deletedDependencyVuln models.DependencyVuln
			err = f.DB.First(&deletedDependencyVuln, "asset_id = ? AND asset_version_name = ?", dependencyVuln.AssetID, dependencyVuln.AssetVersionName).Error
			assert.Equal(t, "record not found", err.Error())

			var deletedFirstPartyVuln models.FirstPartyVuln
			err = f.DB.First(&deletedFirstPartyVuln, "asset_id = ? AND asset_version_name = ?", firstPartyVuln.AssetID, firstPartyVuln.AssetVersionName).Error
			assert.Equal(t, "record not found", err.Error())

			var deletedVulnEvent models.VulnEvent
			err = f.DB.First(&deletedVulnEvent, "vuln_id = ?", vulnEvent.VulnID).Error
			fmt.Println("Deleted Vuln Event:", deletedVulnEvent.ID)
			assert.Equal(t, "record not found", err.Error())
		})
	})
}

func TestDaemonAsssetVersionScan(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

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
			assert.Nil(t, f.DB.Create(&component).Error)

			err := f.DB.Create(&affectedComponent).Error
			assert.Nil(t, err)

			cve := models.CVE{
				CVE:  "CVE-2025-46569",
				CVSS: 8.0,
				AffectedComponents: []*models.AffectedComponent{{
					ID: "1",
				}},
			}

			err = f.DB.Save(&cve).Error
			assert.Nil(t, err)

			// create the artifact
			artifact := models.Artifact{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.Nil(t, f.DB.Create(&artifact).Error)

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
			err = f.DB.Create(&componentDependency).Error
			assert.Nil(t, err)

			// Call ScanArtifacts daemon with FX-injected dependencies
			err = daemons.ScanArtifacts(
				f.DB,
				f.App.ScanController,
				f.App.AssetVersionService,
				f.App.AssetVersionRepository,
				f.App.AssetRepository,
				f.App.ProjectRepository,
				f.App.OrgRepository,
				f.App.ArtifactService,
				f.App.ComponentRepository,
			)
			assert.Nil(t, err)

			var dependencyVuln []models.DependencyVuln

			err = f.DB.Preload("CVE").Find(&dependencyVuln, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, assetVersion.Name, cve.CVE).Error
			assert.Nil(t, err)
			assert.Len(t, dependencyVuln, 1)
			assert.Equal(t, "CVE-2025-46569", dependencyVuln[0].CVE.CVE)
		})
	})
}

func TestDaemonSyncTickets(t *testing.T) {
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	externalUserRepository := mocks.NewExternalUserRepository(t)

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.ExternalUserRepository {
				return externalUserRepository
			}),
		},
	}, func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		org.Slug = "org-slug"
		err := f.DB.Save(&org).Error
		assert.Nil(t, err)
		project.Slug = "project-slug"
		err = f.DB.Save(&project).Error
		assert.Nil(t, err)

		repoID := "gitlab:7c95b7f6-a921-4b27-91ac-38cb94877324:456"
		asset.RepositoryID = &repoID
		cvssThreshold := 7.0
		asset.CVSSAutomaticTicketThreshold = &cvssThreshold
		err = f.DB.Save(&asset).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
		}
		err = f.DB.Save(&cve).Error
		assert.Nil(t, err)

		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
				TicketID:         nil,
				TicketURL:        nil,
				State:            dtos.VulnStateOpen,
				LastDetected:     time.Now(),
			},
			Artifacts: []models.Artifact{{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}},
			CVE:               &cve,
			CVEID:             utils.Ptr(cve.CVE),
			ComponentDepth:    utils.Ptr(1),
			RawRiskAssessment: utils.Ptr(8.0),
		}
		err = f.DB.Create(&dependencyVuln).Error
		assert.Nil(t, err)

		assert.Nil(t, dependencyVuln.TicketID)
		assert.Nil(t, dependencyVuln.TicketURL)

		clientfactory, gitlabClientFacade := NewTestClientFactory(t)

		// Create GitlabIntegration with FX-injected dependencies
		gitlabIntegration := gitlabint.NewGitlabIntegration(
			map[string]*gitlabint.GitlabOauth2Config{},
			f.App.RBACProvider,
			clientfactory,
			f.App.GitlabIntegrationRepository,
			f.App.AggregatedVulnRepository,
			f.App.DependencyVulnRepository,
			f.App.VulnEventRepository,
			f.App.ExternalUserRepository,
			f.App.AssetRepository,
			f.App.AssetVersionRepository,
			f.App.ProjectRepository,
			f.App.ComponentRepository,
			f.App.FirstPartyVulnRepository,
			f.App.GitLabOauth2TokenRepository,
			f.App.LicenseRiskRepository,
			f.App.OrgRepository,
			f.App.OrgService,
			f.App.ProjectService,
			f.App.AssetService,
			f.App.LicenseRiskService,
			f.App.StatisticsService,
		)

		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(externalUserRepository, gitlabIntegration)

		// Capture the create issue call to verify the artifact name is included in the description
		gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.MatchedBy(func(opt *gitlab.CreateIssueOptions) bool {
			// Verify that the issue description contains the artifact name
			if opt.Description == nil {
				return false
			}
			description := *opt.Description
			// The artifact name "artifact1" should be mentioned in the description
			return strings.Contains(description, "artifact1")
		})).Return(
			&gitlab.Issue{
				ID: 12345,
			}, nil, nil)

		gitlabClientFacade.On("CreateIssueComment", mock.Anything, 456, 0, &gitlab.CreateIssueNoteOptions{
			Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
		}).Return(nil, nil, nil)

		// Call SyncTickets daemon with FX-injected dependencies
		err = daemons.SyncTickets(
			f.DB,
			thirdPartyIntegration,
			f.App.DependencyVulnService,
			f.App.AssetVersionRepository,
			f.App.AssetRepository,
			f.App.ProjectRepository,
			f.App.OrgRepository,
			f.App.DependencyVulnRepository,
		)
		assert.Nil(t, err)

		f.DB.Find(&dependencyVuln, "id = ?", dependencyVuln.ID)

		t.Run("should create a ticket with artifact name in description if CVSS is above the threshold", func(t *testing.T) {
			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.TicketID)
			assert.NotNil(t, updatedDependencyVuln.TicketURL)

			// Verify that CreateIssue was called with the artifact name in the description
			gitlabClientFacade.AssertCalled(t, "CreateIssue", mock.Anything, mock.Anything, mock.MatchedBy(func(opt *gitlab.CreateIssueOptions) bool {
				if opt.Description == nil {
					return false
				}
				description := *opt.Description
				// The artifact name "artifact1" should be mentioned in the description
				return strings.Contains(description, "artifact1")
			}))
		})

		t.Run("should not close the ticket if the CVSS is below the threshold but the ticket was manually created", func(t *testing.T) {
			gitlabClientFacade.ExpectedCalls = nil
			gitlabClientFacade.Calls = nil
			// Update the CVSS threshold to a value below the current CVSS
			newCvssThreshold := 9.0
			asset.CVSSAutomaticTicketThreshold = &newCvssThreshold
			err = f.DB.Save(&asset).Error
			assert.Nil(t, err)

			dependencyVuln.ManualTicketCreation = true
			err = f.DB.Save(&dependencyVuln).Error
			assert.Nil(t, err)

			gitlabClientFacade.On("EditIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
				&gitlab.Issue{
					ID:    12345,
					State: "opened",
				}, nil, nil)

			err = daemons.SyncTickets(
				f.DB,
				thirdPartyIntegration,
				f.App.DependencyVulnService,
				f.App.AssetVersionRepository,
				f.App.AssetRepository,
				f.App.ProjectRepository,
				f.App.OrgRepository,
				f.App.DependencyVulnRepository,
			)
			assert.Nil(t, err)

			// Check if the ticket was updated
			editedIssueOptions := gitlabClientFacade.Calls[0].Arguments[3].(*gitlab.UpdateIssueOptions)
			assert.Equal(t, "reopen", *editedIssueOptions.StateEvent)

			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
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
			err = f.DB.Save(&asset).Error
			assert.Nil(t, err)

			dependencyVuln.ManualTicketCreation = false
			err = f.DB.Save(&dependencyVuln).Error
			assert.Nil(t, err)

			gitlabClientFacade.On("EditIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
				&gitlab.Issue{
					ID:    12345,
					State: "closed",
				}, nil, nil)

			err = daemons.SyncTickets(
				f.DB,
				thirdPartyIntegration,
				f.App.DependencyVulnService,
				f.App.AssetVersionRepository,
				f.App.AssetRepository,
				f.App.ProjectRepository,
				f.App.OrgRepository,
				f.App.DependencyVulnRepository,
			)
			assert.Nil(t, err)

			// Check if the ticket was updated
			editedIssueOptions := gitlabClientFacade.Calls[0].Arguments[3].(*gitlab.UpdateIssueOptions)

			assert.Equal(t, "close", *editedIssueOptions.StateEvent)

			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.TicketID)
			assert.NotNil(t, updatedDependencyVuln.TicketURL)
		})
	})
}

func TestTicketDaemonWithMultipleArtifacts(t *testing.T) {
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	externalUserRepository := mocks.NewExternalUserRepository(t)

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.ExternalUserRepository {
				return externalUserRepository
			}),
		},
	}, func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		org.Slug = "org-slug-multi"
		err := f.DB.Save(&org).Error
		assert.Nil(t, err)
		project.Slug = "project-slug-multi"
		err = f.DB.Save(&project).Error
		assert.Nil(t, err)

		repoID := "gitlab:7c95b7f6-a921-4b27-91ac-38cb94877324:456"
		asset.RepositoryID = &repoID
		cvssThreshold := 7.0
		asset.CVSSAutomaticTicketThreshold = &cvssThreshold
		err = f.DB.Save(&asset).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:  "CVE-2025-46570",
			CVSS: 8.5,
		}
		err = f.DB.Save(&cve).Error
		assert.Nil(t, err)

		// Create a vulnerability with multiple artifacts
		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
				TicketID:         nil,
				TicketURL:        nil,
				State:            dtos.VulnStateOpen,
				LastDetected:     time.Now(),
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "package.json", AssetVersionName: assetVersion.Name, AssetID: asset.ID},
				{ArtifactName: "yarn.lock", AssetVersionName: assetVersion.Name, AssetID: asset.ID},
				{ArtifactName: "Dockerfile", AssetVersionName: assetVersion.Name, AssetID: asset.ID},
			},
			CVE:               &cve,
			CVEID:             utils.Ptr(cve.CVE),
			ComponentDepth:    utils.Ptr(1),
			RawRiskAssessment: utils.Ptr(8.5),
		}
		err = f.DB.Create(&dependencyVuln).Error
		assert.Nil(t, err)

		assert.Nil(t, dependencyVuln.TicketID)
		assert.Nil(t, dependencyVuln.TicketURL)

		clientfactory, gitlabClientFacade := NewTestClientFactory(t)

		// Create GitlabIntegration with FX-injected dependencies
		gitlabIntegration := gitlabint.NewGitlabIntegration(
			map[string]*gitlabint.GitlabOauth2Config{},
			f.App.RBACProvider,
			clientfactory,
			f.App.GitlabIntegrationRepository,
			f.App.AggregatedVulnRepository,
			f.App.DependencyVulnRepository,
			f.App.VulnEventRepository,
			f.App.ExternalUserRepository,
			f.App.AssetRepository,
			f.App.AssetVersionRepository,
			f.App.ProjectRepository,
			f.App.ComponentRepository,
			f.App.FirstPartyVulnRepository,
			f.App.GitLabOauth2TokenRepository,
			f.App.LicenseRiskRepository,
			f.App.OrgRepository,
			f.App.OrgService,
			f.App.ProjectService,
			f.App.AssetService,
			f.App.LicenseRiskService,
			f.App.StatisticsService,
		)

		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(externalUserRepository, gitlabIntegration)

		// Capture the create issue call to verify all artifact names are included in the description
		gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.MatchedBy(func(opt *gitlab.CreateIssueOptions) bool {
			if opt.Description == nil {
				return false
			}
			description := *opt.Description
			// All three artifact names should be mentioned in the description
			hasPackageJSON := strings.Contains(description, "package.json")
			hasYarnLock := strings.Contains(description, "yarn.lock")
			hasDockerfile := strings.Contains(description, "Dockerfile")

			return hasPackageJSON && hasYarnLock && hasDockerfile
		})).Return(
			&gitlab.Issue{
				ID: 12346,
			}, nil, nil)

		gitlabClientFacade.On("CreateIssueComment", mock.Anything, 456, 0, &gitlab.CreateIssueNoteOptions{
			Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
		}).Return(nil, nil, nil)

		// Run the ticket daemon with FX-injected dependencies
		err = daemons.SyncTickets(
			f.DB,
			thirdPartyIntegration,
			f.App.DependencyVulnService,
			f.App.AssetVersionRepository,
			f.App.AssetRepository,
			f.App.ProjectRepository,
			f.App.OrgRepository,
			f.App.DependencyVulnRepository,
		)
		assert.Nil(t, err)

		t.Run("should create a ticket with all artifact names in description", func(t *testing.T) {
			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.TicketID)
			assert.NotNil(t, updatedDependencyVuln.TicketURL)

			// Verify that CreateIssue was called with all artifact names in the description
			gitlabClientFacade.AssertCalled(t, "CreateIssue", mock.Anything, mock.Anything, mock.MatchedBy(func(opt *gitlab.CreateIssueOptions) bool {
				if opt.Description == nil {
					return false
				}
				description := *opt.Description
				// All three artifact names should be mentioned in the description
				hasPackageJSON := strings.Contains(description, "`package.json`")
				hasYarnLock := strings.Contains(description, "`yarn.lock`")
				hasDockerfile := strings.Contains(description, "`Dockerfile`")

				return hasPackageJSON && hasYarnLock && hasDockerfile
			}))
		})
	})
}

func TestDaemonRecalculateRisk(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		org.Slug = "org-slug"
		err := f.DB.Save(&org).Error
		assert.Nil(t, err)
		project.Slug = "project-slug"
		err = f.DB.Save(&project).Error
		assert.Nil(t, err)

		asset.AvailabilityRequirement = dtos.RequirementLevelLow
		asset.ConfidentialityRequirement = dtos.RequirementLevelLow
		asset.IntegrityRequirement = dtos.RequirementLevelLow
		err = f.DB.Save(&asset).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:    "CVE-2025-46569",
			CVSS:   8.0,
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
		}
		err = f.DB.Save(&cve).Error
		assert.Nil(t, err)

		oldRawRiskValue := 1.0
		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateOpen,
				LastDetected:     time.Now(),
			},
			Artifacts: []models.Artifact{{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}},
			CVE:               &cve,
			CVEID:             utils.Ptr(cve.CVE),
			ComponentDepth:    utils.Ptr(1),
			RawRiskAssessment: utils.Ptr(oldRawRiskValue),
		}
		err = f.DB.Create(&dependencyVuln).Error
		assert.Nil(t, err)

		t.Run("should recalculate the risk of the dependency vuln", func(t *testing.T) {
			err = daemons.RecalculateRisk(f.App.DependencyVulnService)
			assert.Nil(t, err)

			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.RawRiskAssessment)
			assert.NotEqual(t, oldRawRiskValue, *updatedDependencyVuln.RawRiskAssessment)
		})

		t.Run("should recalculate the risk of the dependency vuln to higher value if the requirements are set to high", func(t *testing.T) {
			asset.AvailabilityRequirement = dtos.RequirementLevelHigh
			asset.ConfidentialityRequirement = dtos.RequirementLevelHigh
			asset.IntegrityRequirement = dtos.RequirementLevelHigh
			err = f.DB.Save(&asset).Error
			assert.Nil(t, err)

			err = f.DB.First(&dependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)
			oldRawRiskValue = *dependencyVuln.RawRiskAssessment

			err = daemons.RecalculateRisk(f.App.DependencyVulnService)
			assert.Nil(t, err)

			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.RawRiskAssessment)
			assert.Greater(t, *updatedDependencyVuln.RawRiskAssessment, oldRawRiskValue)
		})
	})
}

func TestDaemonFixedVersions(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		os.Setenv("FRONTEND_URL", "FRONTEND_URL")

		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		org.Slug = "org-slug"
		err := f.DB.Save(&org).Error
		assert.Nil(t, err)
		project.Slug = "project-slug"
		err = f.DB.Save(&project).Error
		assert.Nil(t, err)

		componentA := models.Component{
			Purl:          "pkg:npm/react@18.2.0",
			ComponentType: dtos.ComponentTypeLibrary,
			Version:       "18.2.0",
		}
		err = f.DB.Create(&componentA).Error
		assert.Nil(t, err)

		componentB := models.Component{
			Purl:          "pkg:npm/react-dom@15.0.0",
			ComponentType: dtos.ComponentTypeLibrary,
			Version:       "15.0.0",
		}
		err = f.DB.Create(&componentB).Error
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
		err = f.DB.Create(&componentDependencyA).Error
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
		err = f.DB.Create(&componentDependencyB).Error
		assert.Nil(t, err)

		affectedComponent := models.AffectedComponent{
			ID:                 "1",
			PurlWithoutVersion: "pkg:npm/react-dom",
			Version:            utils.Ptr("15.0.0"),
			CVE:                []models.CVE{{CVE: "CVE-2025-46569"}},
		}
		err = f.DB.Create(&affectedComponent).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
			AffectedComponents: []*models.AffectedComponent{{
				ID: "1",
			}},
		}
		err = f.DB.Save(&cve).Error
		assert.Nil(t, err)

		artifact := models.Artifact{ArtifactName: "sca", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				ID:               "1",
				AssetID:          asset.ID,
				AssetVersion:     assetVersion,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateOpen,
				LastDetected:     time.Now(),
			},
			CVE:               &cve,
			CVEID:             utils.Ptr(cve.CVE),
			ComponentDepth:    utils.Ptr(3), //this is a wrong value, it should be updated by the daemon
			ComponentPurl:     utils.Ptr("pkg:npm/react-dom@15.0.0"),
			RawRiskAssessment: utils.Ptr(8.0),
			Artifacts:         []models.Artifact{artifact},
		}
		err = f.DB.Create(&dependencyVuln).Error
		assert.Nil(t, err)
		assert.Nil(t, dependencyVuln.ComponentFixedVersion)

		t.Run("should update the component properties, including fixed version and component depth", func(t *testing.T) {
			fixedVersion := "15.0.1"
			dependencyVuln.ComponentFixedVersion = &fixedVersion
			err = f.DB.Save(&dependencyVuln).Error
			assert.Nil(t, err)

			err = daemons.UpdateFixedVersions(f.DB, f.App.DependencyVulnRepository)
			assert.Nil(t, err)

			var updatedDependencyVuln models.DependencyVuln
			err = f.DB.First(&updatedDependencyVuln, "asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Error
			assert.Nil(t, err)

			assert.NotNil(t, updatedDependencyVuln.ComponentFixedVersion)
			assert.Equal(t, fixedVersion, *updatedDependencyVuln.ComponentFixedVersion)
		})
	})
}
