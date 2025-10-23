// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package vuln_test

import (
	"testing"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSyncAllIssuesDuplicateTicketCreation(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create org, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// Configure asset for ticket creation with thresholds that will trigger issue creation
	asset.ConfidentialityRequirement = models.RequirementLevelHigh
	asset.IntegrityRequirement = models.RequirementLevelHigh
	asset.AvailabilityRequirement = models.RequirementLevelHigh
	// Set thresholds to ensure tickets are created
	cvssThreshold := 5.0
	asset.CVSSAutomaticTicketThreshold = &cvssThreshold
	assert.NoError(t, db.Save(&asset).Error)

	t.Run("should create only one ticket when vuln exists in two artifacts", func(t *testing.T) {
		// Create a CVE
		cve := models.CVE{
			CVE:              "CVE-2024-12345",
			Description:      "Test critical vulnerability",
			CVSS:             9.8,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			DatePublished:    assetVersion.CreatedAt,
			DateLastModified: assetVersion.UpdatedAt,
		}
		assert.NoError(t, db.Create(&cve).Error)

		// Create two artifacts
		artifact1 := models.Artifact{
			ArtifactName:     "artifact-1",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		artifact2 := models.Artifact{
			ArtifactName:     "artifact-2",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		assert.NoError(t, db.Create(&artifact1).Error)
		assert.NoError(t, db.Create(&artifact2).Error)

		// Create a dependency vuln associated with both artifacts
		depVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:          utils.Ptr(cve.CVE),
			ComponentPurl:  utils.Ptr("pkg:npm/vulnerable-package@1.0.0"),
			ComponentDepth: utils.Ptr(0),
			Artifacts:      []models.Artifact{artifact1, artifact2},
		}
		assert.NoError(t, db.Create(&depVuln).Error)

		// Set up mock third-party integration
		mockThirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		createIssueCallCount := 0
		mockThirdPartyIntegration.On("CreateIssue",
			mock.Anything, // context
			mock.Anything, // asset
			mock.Anything, // assetVersionSlug
			mock.Anything, // vuln
			mock.Anything, // projectSlug
			mock.Anything, // orgSlug
			mock.Anything, // justification
			mock.Anything, // userID
		).Run(func(args mock.Arguments) {
			createIssueCallCount++
		}).Return(nil).Maybe()

		// Create service with mock
		depVulnRepo := repositories.NewDependencyVulnRepository(db)
		depVulnService := vuln.NewService(
			depVulnRepo,
			repositories.NewVulnEventRepository(db),
			repositories.NewAssetRepository(db),
			repositories.NewCVERepository(db),
			repositories.NewOrgRepository(db),
			repositories.NewProjectRepository(db),
			mockThirdPartyIntegration,
			repositories.NewAssetVersionRepository(db),
		)

		// Call SyncAllIssues
		err := depVulnService.SyncAllIssues(org, project, asset, assetVersion)
		assert.NoError(t, err)

		// Verify CreateIssue was called only once, not twice
		// This is the bug: it gets called twice (once per artifact)
		// Expected behavior: should be called only once since it's the same vulnerability
		assert.Equal(t, 1, createIssueCallCount, "CreateIssue should be called only once for a vulnerability that exists in multiple artifacts")

		// Verify only one ticket ID was assigned
		var vulnFromDB models.DependencyVuln
		err = db.Where("id = ?", depVuln.ID).First(&vulnFromDB).Error
		assert.NoError(t, err)

		assert.Equal(t, 1, createIssueCallCount)
	})

	t.Run("should create separate tickets for different vulnerabilities", func(t *testing.T) {
		// Create a new asset version for this test
		assetVersion2 := models.AssetVersion{
			Name:          "test-branch-2",
			AssetID:       asset.ID,
			DefaultBranch: true, // Must be default branch for ticket creation
			Slug:          "test-branch-2",
			Type:          "branch",
		}
		assert.NoError(t, db.Create(&assetVersion2).Error)

		// Create two different CVEs
		cve1 := models.CVE{
			CVE:              "CVE-2024-11111",
			Description:      "Test high vulnerability 1",
			CVSS:             7.5,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			DatePublished:    assetVersion2.CreatedAt,
			DateLastModified: assetVersion2.UpdatedAt,
		}
		cve2 := models.CVE{
			CVE:              "CVE-2024-22222",
			Description:      "Test high vulnerability 2",
			CVSS:             8.1,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
			DatePublished:    assetVersion2.CreatedAt,
			DateLastModified: assetVersion2.UpdatedAt,
		}
		assert.NoError(t, db.Create(&cve1).Error)
		assert.NoError(t, db.Create(&cve2).Error)

		// Create one artifact
		artifact3 := models.Artifact{
			ArtifactName:     "artifact-3",
			AssetVersionName: assetVersion2.Name,
			AssetID:          asset.ID,
		}
		assert.NoError(t, db.Create(&artifact3).Error)

		// Create two different dependency vulns
		depVuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateOpen,
				AssetVersionName: assetVersion2.Name,
				AssetID:          asset.ID,
			},
			CVEID:          utils.Ptr(cve1.CVE),
			ComponentPurl:  utils.Ptr("pkg:npm/package-a@1.0.0"),
			ComponentDepth: utils.Ptr(0),
			Artifacts:      []models.Artifact{artifact3},
		}
		depVuln2 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateOpen,
				AssetVersionName: assetVersion2.Name,
				AssetID:          asset.ID,
			},
			CVEID:          utils.Ptr(cve2.CVE),
			ComponentPurl:  utils.Ptr("pkg:npm/package-b@2.0.0"),
			ComponentDepth: utils.Ptr(0),
			Artifacts:      []models.Artifact{artifact3},
		}
		assert.NoError(t, db.Create(&depVuln1).Error)
		assert.NoError(t, db.Create(&depVuln2).Error)

		// Set up mock third-party integration
		mockThirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		createIssueCallCount := 0
		mockThirdPartyIntegration.On("CreateIssue",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Run(func(args mock.Arguments) {
			createIssueCallCount++
		}).Return(nil).Maybe()

		// Create service with mock
		depVulnRepo := repositories.NewDependencyVulnRepository(db)
		depVulnService := vuln.NewService(
			depVulnRepo,
			repositories.NewVulnEventRepository(db),
			repositories.NewAssetRepository(db),
			repositories.NewCVERepository(db),
			repositories.NewOrgRepository(db),
			repositories.NewProjectRepository(db),
			mockThirdPartyIntegration,
			repositories.NewAssetVersionRepository(db),
		)

		// Call SyncAllIssues
		err := depVulnService.SyncAllIssues(org, project, asset, assetVersion2)
		assert.NoError(t, err)

		// Verify CreateIssue was called twice (once for each different vulnerability)
		assert.Equal(t, 2, createIssueCallCount, "CreateIssue should be called twice for two different vulnerabilities")
	})
}

func TestSyncIssuesWithExistingTickets(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create org, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// Configure asset
	asset.ConfidentialityRequirement = models.RequirementLevelHigh
	asset.IntegrityRequirement = models.RequirementLevelHigh
	asset.AvailabilityRequirement = models.RequirementLevelHigh
	cvssThreshold := 5.0
	asset.CVSSAutomaticTicketThreshold = &cvssThreshold
	assert.NoError(t, db.Save(&asset).Error)

	t.Run("should update existing ticket when vuln already has ticket ID", func(t *testing.T) {
		// Create a CVE
		cve := models.CVE{
			CVE:              "CVE-2024-99999",
			Description:      "Test critical vulnerability with existing ticket",
			CVSS:             9.0,
			Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			DatePublished:    assetVersion.CreatedAt,
			DateLastModified: assetVersion.UpdatedAt,
		}
		assert.NoError(t, db.Create(&cve).Error)

		// Create artifact
		artifact := models.Artifact{
			ArtifactName:     "artifact-with-ticket",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		assert.NoError(t, db.Create(&artifact).Error)

		// Create a dependency vuln with existing ticket ID
		existingTicketID := "ISSUE-123"
		depVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
				TicketID:         &existingTicketID,
			},
			CVEID:          utils.Ptr(cve.CVE),
			ComponentPurl:  utils.Ptr("pkg:npm/existing-ticket-package@1.0.0"),
			ComponentDepth: utils.Ptr(0),
			Artifacts:      []models.Artifact{artifact},
		}
		assert.NoError(t, db.Create(&depVuln).Error)

		// Set up mock third-party integration
		mockThirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		createIssueCallCount := 0
		updateIssueCallCount := 0

		mockThirdPartyIntegration.On("CreateIssue",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Run(func(args mock.Arguments) {
			createIssueCallCount++
		}).Return(nil).Maybe()

		mockThirdPartyIntegration.On("UpdateIssue",
			mock.Anything, // context
			mock.Anything, // asset
			mock.Anything, // assetVersionSlug
			mock.Anything, // vuln
		).Run(func(args mock.Arguments) {
			updateIssueCallCount++
		}).Return(nil).Maybe()

		// Create service with mock
		depVulnRepo := repositories.NewDependencyVulnRepository(db)
		depVulnService := vuln.NewService(
			depVulnRepo,
			repositories.NewVulnEventRepository(db),
			repositories.NewAssetRepository(db),
			repositories.NewCVERepository(db),
			repositories.NewOrgRepository(db),
			repositories.NewProjectRepository(db),
			mockThirdPartyIntegration,
			repositories.NewAssetVersionRepository(db),
		)

		// Call SyncAllIssues
		err := depVulnService.SyncAllIssues(org, project, asset, assetVersion)
		assert.NoError(t, err)

		// Verify UpdateIssue was called once and CreateIssue was not called
		assert.Equal(t, 0, createIssueCallCount, "CreateIssue should not be called when ticket already exists")
		assert.Equal(t, 1, updateIssueCallCount, "UpdateIssue should be called once when ticket already exists")
	})
}
