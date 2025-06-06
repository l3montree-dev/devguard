package gitlabint_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestGitlabWebhookHandleWebhook(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()
	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	// Setup integration
	gitlabInt := gitlabint.NewGitLabIntegration(
		db,
		nil,
		mocks.NewRBACProvider(t),
		nil,
	)

	// Setup org, asset, asset version, and vuln
	_, _, asset := integration_tests.CreateOrgProjectAndAsset(db)

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

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))

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

		assert.Nil(t, gitlabInt.HandleWebhook(ctx))

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
}
