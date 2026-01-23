package tests

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"go.uber.org/fx"
)

func TestArtifactControllerDeleteArtifact(t *testing.T) {
	factory, client := NewTestClientFactory(t)

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.GitlabClientFactory {
				return factory
			}),
		},
	}, func(f *TestFixture) {
		// Setup: Create org, project, asset, and asset version
		org := f.CreateOrg("test-org-artifact-delete")
		project := f.CreateProject(org.ID, "test-project-artifact-delete")
		asset := f.CreateAsset(project.ID, "test-asset-artifact-delete")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		// Create a gitlab integration and connect the asset
		integration := models.GitLabIntegration{
			OrgID: org.ID,
		}
		assert.NoError(t, f.DB.Create(&integration).Error)

		asset.RepositoryID = utils.Ptr("gitlab:" + integration.ID.String() + ":123")
		assert.NoError(t, f.DB.Save(&asset).Error)

		// Create multiple artifacts
		artifact1 := models.Artifact{
			ArtifactName:     "artifact-1",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		assert.NoError(t, f.DB.Create(&artifact1).Error)

		artifact2 := models.Artifact{
			ArtifactName:     "artifact-2",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		assert.NoError(t, f.DB.Create(&artifact2).Error)

		// Create a CVE
		cve := models.CVE{
			CVE:  "CVE-2025-DELETE-001",
			CVSS: 7.5,
		}
		assert.NoError(t, f.DB.Create(&cve).Error)

		// Create components (required by foreign key constraint)
		component1 := models.Component{
			ID: "pkg:npm/vulnerable-package@1.0.0",
		}
		assert.NoError(t, f.DB.Create(&component1).Error)

		component2 := models.Component{
			ID: "pkg:npm/multi-artifact-package@1.0.0",
		}
		assert.NoError(t, f.DB.Create(&component2).Error)

		t.Run("should close ticket for vulnerability that only belongs to deleted artifact", func(t *testing.T) {
			// Create a vulnerability that only belongs to artifact1
			vuln1 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
					TicketID:         utils.Ptr("gitlab:123/456"),
				},
				CVEID:             cve.CVE,
				ComponentPurl:     "pkg:npm/vulnerable-package@1.0.0",
				VulnerabilityPath: []string{"root", "artifact:artifact-1", "pkg:npm/vulnerable-package@1.0.0"},
				Artifacts: []models.Artifact{
					artifact1,
				},
			}
			assert.NoError(t, f.DB.Create(&vuln1).Error)

			// Mock gitlab client to expect issue update (closing the ticket)
			client.On("EditIssue", mock.Anything, 123, 456, mock.MatchedBy(func(opts *gitlab.UpdateIssueOptions) bool {
				return opts.StateEvent != nil && *opts.StateEvent == "close"
			})).Return(&gitlab.Issue{}, &gitlab.Response{}, nil).Once()

			// Mock IsProjectMember call for authorization check
			client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

			// Debug: check what's available
			assert.NotNil(t, f.App.ArtifactController, "ArtifactController should not be nil")
			assert.NotNil(t, f.App.DependencyVulnRepository, "DependencyVulnRepository should not be nil")
			assert.NotNil(t, f.App.DependencyVulnService, "DependencyVulnService should not be nil")

			// Create echo context for delete request
			e := echo.New()
			req := httptest.NewRequest("DELETE", "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Set context values
			ctx.Set("organization", org)
			ctx.Set("project", project)
			ctx.Set("asset", asset)
			ctx.Set("assetVersion", assetVersion)
			ctx.Set("artifact", artifact1)
			ctx.Set("session", NewSessionMock("test-user"))

			// Execute delete
			err := f.App.ArtifactController.DeleteArtifact(ctx)
			assert.NoError(t, err)

			// Wait for Fire and Forget to complete
			time.Sleep(500 * time.Millisecond)

			// Verify artifact was deleted
			var deletedArtifact models.Artifact
			err = f.DB.First(&deletedArtifact, "artifact_name = ? AND asset_id = ?", artifact1.ArtifactName, asset.ID).Error
			assert.Error(t, err, "Artifact should be deleted")

			// Verify the gitlab client was called to close the issue
			// (the vulnerability will be deleted along with the artifact since it only belonged to this artifact)
			client.AssertExpectations(t)
		})

		t.Run("should not close ticket for vulnerability that belongs to multiple artifacts", func(t *testing.T) {
			// Create a vulnerability that belongs to both artifacts
			vuln2 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
					TicketID:         utils.Ptr("gitlab:123/789"),
				},
				CVEID:             cve.CVE,
				ComponentPurl:     "pkg:npm/multi-artifact-package@1.0.0",
				VulnerabilityPath: []string{"root", "artifact:artifact-1", "pkg:npm/multi-artifact-package@1.0.0"},
				Artifacts: []models.Artifact{
					artifact1,
					artifact2,
				},
			}
			assert.NoError(t, f.DB.Create(&vuln2).Error)

			// Create echo context for delete request
			e := echo.New()
			req := httptest.NewRequest("DELETE", "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Set context values
			ctx.Set("organization", org)
			ctx.Set("project", project)
			ctx.Set("asset", asset)
			ctx.Set("assetVersion", assetVersion)
			ctx.Set("artifact", artifact1)
			ctx.Set("session", NewSessionMock("test-user"))

			// Execute delete
			err := f.App.ArtifactController.DeleteArtifact(ctx)
			assert.NoError(t, err)

			// Verify vulnerability still exists and is still open
			var updatedVuln models.DependencyVuln
			assert.NoError(t, f.DB.Preload("Artifacts").First(&updatedVuln, "id = ?", vuln2.ID).Error)
			assert.Equal(t, dtos.VulnStateOpen, updatedVuln.State, "Vulnerability should remain open since it belongs to another artifact")

			// Verify no gitlab update was called for this vulnerability
			// (the mock would fail if an unexpected call was made)
		})

		t.Run("should handle deletion when no vulnerabilities are affected", func(t *testing.T) {
			// Create an artifact with no vulnerabilities
			artifact3 := models.Artifact{
				ArtifactName:     "artifact-3-no-vulns",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifact3).Error)

			// Create echo context for delete request
			e := echo.New()
			req := httptest.NewRequest("DELETE", "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Set context values
			ctx.Set("organization", org)
			ctx.Set("project", project)
			ctx.Set("asset", asset)
			ctx.Set("assetVersion", assetVersion)
			ctx.Set("artifact", artifact3)
			ctx.Set("session", NewSessionMock("test-user"))

			// Execute delete
			err := f.App.ArtifactController.DeleteArtifact(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			// Verify artifact was deleted
			var deletedArtifact models.Artifact
			err = f.DB.First(&deletedArtifact, "artifact_name = ? AND asset_id = ?", artifact3.ArtifactName, asset.ID).Error
			assert.Error(t, err, "Artifact should be deleted")
		})
	})
}
