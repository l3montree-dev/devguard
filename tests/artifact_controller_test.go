package tests

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
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

		t.Run("should delete dependency vuln when it only belongs to the deleted artifact", func(t *testing.T) {
			// Create a new artifact for this test
			artifactSingle := models.Artifact{
				ArtifactName:     "artifact-single-vuln",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifactSingle).Error)

			// Create a component for this test
			componentSingle := models.Component{
				ID: "pkg:npm/single-artifact-vuln-package@1.0.0",
			}
			assert.NoError(t, f.DB.Create(&componentSingle).Error)

			// Create a vulnerability that only belongs to this artifact
			vulnSingle := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
				},
				CVEID:             cve.CVE,
				ComponentPurl:     componentSingle.ID,
				VulnerabilityPath: []string{"root", "artifact:artifact-single-vuln", componentSingle.ID},
				Artifacts: []models.Artifact{
					artifactSingle,
				},
			}
			assert.NoError(t, f.DB.Create(&vulnSingle).Error)

			// Verify vulnerability exists before deletion
			var vulnBefore models.DependencyVuln
			assert.NoError(t, f.DB.First(&vulnBefore, "id = ?", vulnSingle.ID).Error)

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
			ctx.Set("artifact", artifactSingle)
			ctx.Set("session", NewSessionMock("test-user"))

			// Execute delete
			err := f.App.ArtifactController.DeleteArtifact(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			// Verify artifact was deleted
			var deletedArtifact models.Artifact
			err = f.DB.First(&deletedArtifact, "artifact_name = ? AND asset_id = ?", artifactSingle.ArtifactName, asset.ID).Error
			assert.Error(t, err, "Artifact should be deleted")

			// Verify the dependency vulnerability was also deleted
			var vulnAfter models.DependencyVuln
			err = f.DB.First(&vulnAfter, "id = ?", vulnSingle.ID).Error
			assert.Error(t, err, "Dependency vulnerability should be deleted when its only artifact is deleted")
		})

		t.Run("should keep dependency vuln but remove artifact relation when vuln belongs to multiple artifacts", func(t *testing.T) {
			// Create two artifacts for this test
			artifactMulti1 := models.Artifact{
				ArtifactName:     "artifact-multi-1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifactMulti1).Error)

			artifactMulti2 := models.Artifact{
				ArtifactName:     "artifact-multi-2",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifactMulti2).Error)

			// Create a component for this test
			componentMulti := models.Component{
				ID: "pkg:npm/multi-artifact-vuln-package@2.0.0",
			}
			assert.NoError(t, f.DB.Create(&componentMulti).Error)

			// Create a vulnerability that belongs to both artifacts
			vulnMulti := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
				},
				CVEID:             cve.CVE,
				ComponentPurl:     componentMulti.ID,
				VulnerabilityPath: []string{"root", "artifact:artifact-multi-1", componentMulti.ID},
				Artifacts: []models.Artifact{
					artifactMulti1,
					artifactMulti2,
				},
			}
			assert.NoError(t, f.DB.Create(&vulnMulti).Error)

			// Verify vulnerability exists with two artifacts before deletion
			var vulnBefore models.DependencyVuln
			assert.NoError(t, f.DB.Preload("Artifacts").First(&vulnBefore, "id = ?", vulnMulti.ID).Error)
			assert.Len(t, vulnBefore.Artifacts, 2, "Vulnerability should have 2 artifacts before deletion")

			// Create echo context for delete request - delete artifact 1
			e := echo.New()
			req := httptest.NewRequest("DELETE", "/", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Set context values
			ctx.Set("organization", org)
			ctx.Set("project", project)
			ctx.Set("asset", asset)
			ctx.Set("assetVersion", assetVersion)
			ctx.Set("artifact", artifactMulti1)
			ctx.Set("session", NewSessionMock("test-user"))

			// Execute delete
			err := f.App.ArtifactController.DeleteArtifact(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			// Verify artifact1 was deleted
			var deletedArtifact models.Artifact
			err = f.DB.First(&deletedArtifact, "artifact_name = ? AND asset_id = ?", artifactMulti1.ArtifactName, asset.ID).Error
			assert.Error(t, err, "Artifact1 should be deleted")

			// Verify artifact2 still exists
			var remainingArtifact models.Artifact
			err = f.DB.First(&remainingArtifact, "artifact_name = ? AND asset_id = ?", artifactMulti2.ArtifactName, asset.ID).Error
			assert.NoError(t, err, "Artifact2 should still exist")

			// Verify the dependency vulnerability still exists
			var vulnAfter models.DependencyVuln
			err = f.DB.Preload("Artifacts").First(&vulnAfter, "id = ?", vulnMulti.ID).Error
			assert.NoError(t, err, "Dependency vulnerability should still exist when it has remaining artifacts")

			// Verify the vulnerability now only has one artifact (the remaining one)
			assert.Len(t, vulnAfter.Artifacts, 1, "Vulnerability should have only 1 artifact after deletion")
			assert.Equal(t, artifactMulti2.ArtifactName, vulnAfter.Artifacts[0].ArtifactName, "Remaining artifact should be artifact-multi-2")
		})
	})
}

func TestBuildVEX(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		artifactName := "test-artifact"

		setupContext := func(ctx *shared.Context) {
			// set basic context values
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)
			shared.SetArtifact(*ctx, models.Artifact{ArtifactName: artifactName, AssetVersionName: assetVersion.Name, AssetID: asset.ID})
		}
		t.Run("test with empty db should return err, since artifact does not exist", func(t *testing.T) {
			//setup function call
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/vex-json/", nil)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)
			err := f.App.ArtifactController.VEXJSON(ctx)
			assert.Error(t, err)
		})
		vuln1, vuln2 := createDependencyVulnsForAssetControllerTest(f.DB, asset.ID, assetVersion.Name, artifactName)
		t.Run("build Vex with everything set as intended", func(t *testing.T) {
			//setup function call
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/vex-json/", nil)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)
			err := f.App.ArtifactController.VEXJSON(ctx)
			assert.Nil(t, err)

			//prep results for testing
			resp := recorder.Result()
			body, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)
			var VEXResult cyclonedx.BOM
			err = json.Unmarshal(body, &VEXResult)
			assert.Nil(t, err)

			//test Vulnerability id as well as purls
			assert.Len(t, *VEXResult.Vulnerabilities, 2)

			// Find vulnerabilities by component PURL (order is not guaranteed)
			var nextVuln, axiosVuln *cyclonedx.Vulnerability
			for i := range *VEXResult.Vulnerabilities {
				v := &(*VEXResult.Vulnerabilities)[i]
				if len(*v.Affects) > 0 && (*v.Affects)[0].Ref == "pkg:npm/next@14.2.13" {
					nextVuln = v
				} else if len(*v.Affects) > 0 && (*v.Affects)[0].Ref == "pkg:npm/axios@1.7.7" {
					axiosVuln = v
				}
			}

			assert.NotNil(t, nextVuln, "Should find next vulnerability")
			assert.NotNil(t, axiosVuln, "Should find axios vulnerability")

			assert.Equal(t, "CVE-2024-51479", nextVuln.ID)
			assert.Equal(t, "CVE-2024-51479", axiosVuln.ID)
			assert.Equal(t, "pkg:npm/next@14.2.13", (*nextVuln.Affects)[0].Ref)
			assert.Equal(t, "pkg:npm/axios@1.7.7", (*axiosVuln.Affects)[0].Ref)

			//test timestamps if they have the right format
			propertyValue1 := (*nextVuln.Properties)[0].Value
			responseTime1, err := time.Parse(time.RFC3339, propertyValue1)
			assert.Nil(t, err)
			propertyValue2 := (*axiosVuln.Properties)[0].Value
			responseTime2, err := time.Parse(time.RFC3339, propertyValue2)
			assert.Nil(t, err)
			//test if the first responded timestamp is calculated about right
			assert.True(t, responseTime1.Before(time.Now().Add(-7*time.Minute).UTC()) && responseTime1.After(time.Now().Add(-7*time.Minute-time.Second).UTC()))
			assert.True(t, responseTime2.Before(time.Now().Add(-1*time.Minute)) && responseTime2.After(time.Now().Add(-1*time.Minute-time.Second)))
			//last updated should be the same as first responded when only 1 updateEvent happens
			assert.Equal(t, axiosVuln.Analysis.LastUpdated, (*axiosVuln.Properties)[0].Value)
		})

		t.Run("build Vex but one vuln never gets handled should return empty properties for that vulnerability", func(t *testing.T) {
			//setup function call
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/vex-json/", nil)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)
			if err := f.DB.Delete(&models.VulnEvent{}, "vuln_id = ? AND type = ?", vuln2.ID, "fixed").Error; err != nil {
				panic(err)
			}

			err := f.App.ArtifactController.VEXJSON(ctx)
			assert.Nil(t, err)

			//prep results for testing
			resp := recorder.Result()
			body, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)

			var VEXResult cyclonedx.BOM
			err = json.Unmarshal(body, &VEXResult)
			assert.Nil(t, err)

			// Find the axios vulnerability (vuln2) by PURL since order is not guaranteed
			var axiosVuln *cyclonedx.Vulnerability
			for i := range *VEXResult.Vulnerabilities {
				v := &(*VEXResult.Vulnerabilities)[i]
				if len(*v.Affects) > 0 && (*v.Affects)[0].Ref == "pkg:npm/axios@1.7.7" {
					axiosVuln = v
					break
				}
			}
			assert.NotNil(t, axiosVuln, "Should find axios vulnerability")

			//if the vulnerability never gets handled we should have no first responded field and first issued and last updated should be the same
			assert.Nil(t, axiosVuln.Properties)
			assert.Equal(t, axiosVuln.Analysis.FirstIssued, axiosVuln.Analysis.LastUpdated)
		})

		t.Run("should not list vulnerabilities which are already fixed", func(t *testing.T) {
			//setup function call
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/vex-json/", nil)
			ctx := app.NewContext(req, recorder)
			setupContext(&ctx)

			// update the vuln1 to be fixed
			vuln1.State = "fixed"
			if err := f.DB.Save(&vuln1).Error; err != nil {
				panic(err)
			}
			err := f.App.ArtifactController.VEXJSON(ctx)
			assert.Nil(t, err)

			//prep results for testing
			resp := recorder.Result()
			body, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)

			var VEXResult cyclonedx.BOM
			err = json.Unmarshal(body, &VEXResult)
			assert.Nil(t, err)

			assert.Len(t, *VEXResult.Vulnerabilities, 1)
			assert.Equal(t, (*VEXResult.Vulnerabilities)[0].ID, "CVE-2024-51479")
		})
	})
}
func createDependencyVulnsForAssetControllerTest(db shared.DB, assetID uuid.UUID, assetVersionName string, artifactName string) (models.DependencyVuln, models.DependencyVuln) {

	var err error

	cve := models.CVE{
		CVE:         "CVE-2024-51479",
		Description: "Test usage",
		CVSS:        7.50,
	}
	if err = db.Create(&cve).Error; err != nil {
		panic(err)
	}
	//create an exploit for the cve
	exploit := models.Exploit{
		ID:       "exploitdb:1",
		CVE:      cve,
		CVEID:    cve.CVE,
		Author:   "mats schummels",
		Verified: false,
	}
	if err = db.Create(&exploit).Error; err != nil {
		panic(err)
	}

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersionName,
		AssetID:          assetID,
	}
	if err := db.Create(&artifact).Error; err != nil {
		panic(err)
	}

	// create the components referenced by the dependency vulns
	component1 := models.Component{
		ID: "pkg:npm/next@14.2.13",
	}
	if err = db.Create(&component1).Error; err != nil {
		panic(err)
	}
	component2 := models.Component{
		ID: "pkg:npm/axios@1.7.7",
	}
	if err = db.Create(&component2).Error; err != nil {
		panic(err)
	}

	//create our 2 dependency vuln referencing the cve
	vuln1 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     "pkg:npm/next@14.2.13",
		CVE:               cve,
		CVEID:             cve.CVE,
		RawRiskAssessment: utils.Ptr(4.83),
		Artifacts:         []models.Artifact{artifact},
		VulnerabilityPath: []string{"root", "artifact:test", "pkg:npm/next@14.2.13"},
	}
	if err = db.Create(&vuln1).Error; err != nil {
		panic(err)
	}
	vuln2 := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     "pkg:npm/axios@1.7.7",
		CVE:               cve,
		CVEID:             cve.CVE,
		RawRiskAssessment: utils.Ptr(8.89),
		Artifacts:         []models.Artifact{artifact},
		VulnerabilityPath: []string{"root", "artifact:test", "pkg:npm/axios@1.7.7"},
	}
	if err = db.Create(&vuln2).Error; err != nil {
		panic(err)
	}

	// save the relation to the artifact
	if err = db.Model(&artifact).Association("DependencyVuln").Append(&vuln1, &vuln2); err != nil {
		panic(err)
	}

	//lastly create the vuln events regarding the two dependency vulns where as one dependencyVuln has 2 updates and the other one just has 1 update being the fix
	vuln1DetectedEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-10 * time.Minute), UpdatedAt: time.Now().Add(-5 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln1CommentEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-7 * time.Minute), UpdatedAt: time.Now().Add(-7 * time.Minute)},
		Type:     "comment",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1CommentEvent).Error; err != nil {
		panic(err)
	}
	vuln1FixedEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-3 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1FixedEvent).Error; err != nil {
		panic(err)
	}
	vuln2DetectedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-2 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln2FixedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-1 * time.Minute), UpdatedAt: time.Now().Add(-1 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2FixedEvent).Error; err != nil {
		panic(err)
	}
	return vuln1, vuln2
}
