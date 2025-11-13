package gitlabint_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestGitlabWebhookHandleWebhook(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()
	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	factory, client := integration_tests.NewTestClientFactory(t)
	// Setup integration
	gitlabInt := gitlabint.NewGitlabIntegration(
		db,
		nil,
		mocks.NewRBACProvider(t),
		factory,
	)

	// Setup org, asset, asset version, and vuln
	org, _, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	// create a gitlab integration
	integration := models.GitLabIntegration{
		OrgID: org.ID,
	}
	assert.Nil(t, db.Create(&integration).Error)

	// connect the asset to gitlab
	asset.RepositoryID = utils.Ptr("gitlab:" + integration.ID.String() + ":1")
	assert.Nil(t, db.Save(&asset).Error)
	// create a asset version
	assetVersion := models.AssetVersion{
		AssetID:       asset.ID,
		Name:          "1.0.0",
		DefaultBranch: true,
	}
	assert.Nil(t, db.Create(&assetVersion).Error)

	// add a vulnerability to the asset version
	vuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			State:            models.VulnStateOpen,
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
			TicketID:         utils.Ptr("gitlab:0/123"),
		},
	}
	assert.Nil(t, db.Create(&vuln).Error)

	t.Run("should do nothing if the event user is the same as the author of the issue (author HAS to be devguard - we only want to look at devguard tickets - thus event user is devguard)", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 1,
				"iid":       123,
				"action":    "close",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))
		// expect the vuln to still be open
		vulnFromDB := models.DependencyVuln{}
		assert.Nil(t, db.First(&vulnFromDB, "id = ?", vuln.ID).Error)
		assert.Equal(t, models.VulnStateOpen, vulnFromDB.State)
	})

	t.Run("should do nothing, if there is no ticket with the given id", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 2,
				"iid":       999, // non-existing ticket id
				"action":    "close",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))
	})

	t.Run("should validate the webhook secret token and return an error if it doesnt match", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 2,
				"iid":       123,
				"action":    "open",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")
		req.Header.Set("X-Gitlab-Token", "invalid-token")
		// add an webhook secret to the asset
		asset.WebhookSecret = utils.Ptr(uuid.New())
		db.Save(&asset)

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		err = gitlabInt.HandleWebhook(ctx)
		assert.NotNil(t, err)
		assert.Equal(t, "invalid webhook secret", err.Error())
	})

	t.Run("should close the ticket and set the vuln state to closed", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 2,
				"iid":       123,
				"action":    "close",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)
		webhookSecret := uuid.New()
		asset.WebhookSecret = &webhookSecret
		assert.Nil(t, db.Save(&asset).Error)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")
		req.Header.Set("X-Gitlab-Token", webhookSecret.String())

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		client.On("EditIssue", mock.Anything, mock.Anything, 123, mock.Anything).Return(nil, nil, nil).Once()
		// expect the gitlab update issue options to have a close and accepted label

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))
		options := client.Calls[0].Arguments.Get(3).(*gitlab.UpdateIssueOptions)

		assert.Equal(t, utils.Ptr("close"), options.StateEvent)
		assert.Equal(t, options.Labels, utils.Ptr(gitlab.LabelOptions([]string{"devguard", "state:accepted"})))

		vulnFromDB := models.DependencyVuln{}
		assert.Nil(t, db.First(&vulnFromDB, "id = ?", vuln.ID).Error)
		assert.Equal(t, models.VulnStateAccepted, vulnFromDB.State)
	})

	t.Run("should reopen the ticket, if the action is reopen and the vuln isnt open", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 2,
				"iid":       123,
				"action":    "reopen",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)
		// make sure to close the vuln first
		vuln.State = models.VulnStateAccepted
		assert.Nil(t, db.Save(&vuln).Error)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")
		req.Header.Set("X-Gitlab-Token", asset.WebhookSecret.String())

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		client.Calls = nil // reset the calls to the client
		client.ExpectedCalls = nil

		client.On("EditIssue", mock.Anything, mock.Anything, 123, mock.Anything).Return(nil, nil, nil).Once()

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))
		options := client.Calls[0].Arguments.Get(3).(*gitlab.UpdateIssueOptions)

		assert.Equal(t, utils.Ptr("reopen"), options.StateEvent)
		assert.Equal(t, options.Labels, utils.Ptr(gitlab.LabelOptions([]string{"devguard", "state:open"})))

		vulnFromDB := models.DependencyVuln{}
		assert.Nil(t, db.First(&vulnFromDB, "id = ?", vuln.ID).Error)
		assert.Equal(t, models.VulnStateOpen, vulnFromDB.State)
	})

	t.Run("should not reopen the vulnerability, if the ticket is reopened but the vulnerability is fixed", func(t *testing.T) {
		issueEvent := map[string]any{
			"user": map[string]any{
				"id": 1,
			},
			"object_attributes": map[string]any{
				"author_id": 2,
				"iid":       123,
				"action":    "reopen",
			},
		}
		b, err := json.Marshal(issueEvent)
		assert.Nil(t, err)
		// make sure to close the vuln first
		vuln.State = models.VulnStateFixed
		assert.Nil(t, db.Save(&vuln).Error)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Issue Hook")
		req.Header.Set("X-Gitlab-Token", asset.WebhookSecret.String())

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))

		vulnFromDB := models.DependencyVuln{}
		assert.Nil(t, db.First(&vulnFromDB, "id = ?", vuln.ID).Error)
		assert.Equal(t, models.VulnStateFixed, vulnFromDB.State)
	})

	t.Run("should regenerate risk history when vulnerability state changes via comment", func(t *testing.T) {
		// Reset vuln state to open for this test
		vuln.State = models.VulnStateOpen
		assert.Nil(t, db.Save(&vuln).Error)

		// Create an artifact associated with the vulnerability
		artifact := models.Artifact{
			ArtifactName:     "test-artifact-comment",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		assert.Nil(t, db.Create(&artifact).Error)

		// Associate the artifact with the vulnerability
		assert.Nil(t, db.Model(&vuln).Association("Artifacts").Append(&artifact))

		// Pre-create an artifact risk history record for today to see if it gets updated
		artifactRiskHistory := models.ArtifactRiskHistory{
			ArtifactName:     artifact.ArtifactName,
			AssetVersionName: artifact.AssetVersionName,
			AssetID:          artifact.AssetID,
			History: models.History{
				Day: time.Now().UTC(),
				Distribution: models.Distribution{
					Critical: 1,
				},
			},
		}
		assert.Nil(t, db.Create(&artifactRiskHistory).Error)

		// Test a comment event that changes vulnerability state to accepted
		// Note Hook events have different structure than Issue Hook events according to GitLab documentation
		commentEvent := map[string]any{
			"object_kind":   "note",
			"noteable_type": "Issue", // try uppercase again
			"user": map[string]any{
				"id":       2,
				"username": "testuser",
			},
			"issue": map[string]any{
				"iid": 123,
			},
			"project_id": 0,
			"object_attributes": map[string]any{
				"note":          "/accept This vulnerability is acceptable for our use case",
				"noteable_type": "Issue",
			},
		}
		b, err := json.Marshal(commentEvent)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(b))
		req.Header.Set("X-Gitlab-Event", "Note Hook")
		req.Header.Set("X-Gitlab-Token", asset.WebhookSecret.String())

		rec := httptest.NewRecorder()
		app := echo.New()
		ctx := app.NewContext(req, rec)

		client.Calls = nil // reset the calls to the client
		client.ExpectedCalls = nil

		// Mock the user authorization check - IsProjectMember expects (ctx, projectID, userID, accessLevel)
		client.On("IsProjectMember", mock.Anything, 0, 2, mock.Anything).Return(true, nil).Once()
		client.On("EditIssue", mock.Anything, 0, 123, mock.Anything).Return(nil, nil, nil).Once()

		// Check if there are any artifact risk history records before the webhook call
		var artifactRiskHistoryBefore models.ArtifactRiskHistory
		err = db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ? AND day = CURRENT_DATE",
			artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID).
			Find(&artifactRiskHistoryBefore).Error
		assert.Nil(t, err, "Should find artifact risk history record for today before webhook processing")

		assert.Equal(t, 1, artifactRiskHistoryBefore.Critical, "Critical risk count should be 1 before processing comment")

		// Call the webhook handler
		assert.Nil(t, gitlabInt.HandleWebhook(ctx))

		// Verify the vulnerability state changed to accepted
		vulnFromDB := models.DependencyVuln{}
		assert.Nil(t, db.Preload("Artifacts").First(&vulnFromDB, "id = ?", vuln.ID).Error)
		assert.Equal(t, models.VulnStateAccepted, vulnFromDB.State)

		// Verify that the vulnerability has artifacts
		assert.NotEmpty(t, vulnFromDB.GetArtifacts(), "Vulnerability should have associated artifacts for risk history update")

		// Verify that risk history was updated for today's date
		var artifactRiskHistoryAfter models.ArtifactRiskHistory
		err = db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ? AND day = CURRENT_DATE",
			artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID).
			Find(&artifactRiskHistoryAfter).Error
		assert.Nil(t, err, "Should find artifact risk history record for today after webhook processing")

		assert.Equal(t, artifactRiskHistoryAfter.Critical, 0, "Critical risk count should be 0")

	})

}
