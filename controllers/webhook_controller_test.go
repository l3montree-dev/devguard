// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWebhookControllerUpdate(t *testing.T) {
	e := echo.New()

	t.Run("keeps the stored createdAt instead of writing a zero time", func(t *testing.T) {
		integrationID := uuid.New()
		orgID := uuid.New()
		projectID := uuid.New()
		createdAt := time.Date(2026, 8, 12, 13, 59, 38, 0, time.UTC)

		repository := mocks.NewWebhookIntegrationRepository(t)
		repository.EXPECT().GetClientByIntegrationID(mock.Anything, mock.Anything, integrationID).Return(models.WebhookIntegration{
			Model:     models.Model{ID: integrationID, CreatedAt: createdAt},
			URL:       "https://example.com/old",
			OrgID:     orgID,
			ProjectID: &projectID,
		}, nil)

		var saved *models.WebhookIntegration
		repository.EXPECT().Save(mock.Anything, mock.Anything, mock.Anything).Run(func(ctx context.Context, tx shared.DB, model *models.WebhookIntegration) {
			saved = model
		}).Return(nil)

		body := `{"id":"` + integrationID.String() + `","name":"n","description":"d","url":"https://example.com/new","sbomEnabled":true,"vulnEnabled":true}`
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		controller := NewWebhookController(repository)
		err := controller.Update(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NotNil(t, saved)
		assert.Equal(t, createdAt, saved.CreatedAt)
		assert.Equal(t, orgID, saved.OrgID)
		assert.Equal(t, &projectID, saved.ProjectID)
	})
}
