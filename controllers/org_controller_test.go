package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOrgControllerGetConfigFile(t *testing.T) {
	e := echo.New()

	t.Run("returns 200 with config file content when found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("devguard.yaml")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"devguard.yaml": "config-content",
			},
		})

		controller := &OrgController{}
		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "config-content", rec.Body.String())
	})

	t.Run("returns 404 when config file is not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("missing.yaml")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{},
		})

		controller := &OrgController{}
		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("returns 404 when org has no config files", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("devguard.yaml")

		shared.SetOrg(ctx, models.Org{})

		controller := &OrgController{}
		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestOrgControllerUpdateConfigFile(t *testing.T) {
	e := echo.New()

	t.Run("creates config file and returns 200 with content", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader("new-config-content"))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("devguard.yaml")

		shared.SetOrg(ctx, models.Org{})

		mockRepo := mocks.NewOrganizationRepository(t)
		mockRepo.On("Update", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		controller := &OrgController{organizationRepository: mockRepo}
		err := controller.UpdateConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "new-config-content", rec.Body.String())
	})

	t.Run("deletes config file when body is empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(""))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("devguard.yaml")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"devguard.yaml": "existing-content",
			},
		})

		mockRepo := mocks.NewOrganizationRepository(t)
		mockRepo.On("Update", mock.Anything, mock.Anything, mock.MatchedBy(func(org *models.Org) bool {
			_, exists := org.ConfigFiles["devguard.yaml"]
			return !exists
		})).Return(nil)

		controller := &OrgController{organizationRepository: mockRepo}
		err := controller.UpdateConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("returns 400 when config-file param is empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader("content"))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("")

		shared.SetOrg(ctx, models.Org{})

		controller := &OrgController{}
		err := controller.UpdateConfigFile(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("returns 500 when repository update fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader("content"))
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("devguard.yaml")

		shared.SetOrg(ctx, models.Org{})

		mockRepo := mocks.NewOrganizationRepository(t)
		mockRepo.On("Update", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db error"))

		controller := &OrgController{organizationRepository: mockRepo}
		err := controller.UpdateConfigFile(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	})
}

func TestOrgControllerAdminSettings(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	webhookName := "Alerts"
	webhookDescription := "Security alerts"
	org := models.Org{
		Name: "DevGuard",
		Slug: "devguard",
		Webhooks: []models.WebhookIntegration{{
			Name:        &webhookName,
			Description: &webhookDescription,
			URL:         "https://example.com/webhook",
			SbomEnabled: true,
			VulnEnabled: true,
		}},
	}
	shared.SetOrg(ctx, org)

	mockRBAC := mocks.NewAccessControl(t)
	mockRBAC.On("GetAllMembersOfOrganization").Return([]string{}, nil)
	shared.SetRBAC(ctx, mockRBAC)

	mockIntegrations := mocks.NewIntegrationAggregate(t)
	mockIntegrations.On("GetUsers", org).Return([]dtos.UserDTO{})
	shared.SetThirdPartyIntegration(ctx, mockIntegrations)

	controller := &OrgController{}
	err := controller.AdminSettings(ctx)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response dtos.OrgSettingsDTO
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, org.Name, response.Name)
	assert.Equal(t, org.Slug, response.Slug)
	assert.Empty(t, response.Members)
	assert.Len(t, response.Webhooks, 1)
	assert.Equal(t, "https://example.com/webhook", response.Webhooks[0].URL)
}

func TestOrgControllerReadDoesNotExposeWebhooks(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	webhookName := "Alerts"
	webhookDescription := "Security alerts"
	org := models.Org{
		Name: "DevGuard",
		Slug: "devguard",
		Webhooks: []models.WebhookIntegration{{
			Name:        &webhookName,
			Description: &webhookDescription,
			URL:         "https://example.com/webhook",
		}},
	}
	shared.SetOrg(ctx, org)

	mockRBAC := mocks.NewAccessControl(t)
	mockRBAC.On("GetAllMembersOfOrganization").Return([]string{}, nil)
	shared.SetRBAC(ctx, mockRBAC)

	mockIntegrations := mocks.NewIntegrationAggregate(t)
	mockIntegrations.On("GetUsers", org).Return([]dtos.UserDTO{})
	shared.SetThirdPartyIntegration(ctx, mockIntegrations)

	controller := &OrgController{}
	err := controller.Read(ctx)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]any
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, org.Name, response["name"])
	assert.NotContains(t, response, "webhooks")
}

// Test function for Create and bootstrap from org_controller
func TestCreate(t *testing.T) {
	t.Run("Should fail if a context with wrong parameters is provided", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString("fantasy"))

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		h := NewOrganizationController(nil, nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Should fail if the context is in the wrong format", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", nil)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{Name: "fantasy", Slug: "fantasy"})

		h := NewOrganizationController(nil, nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("should fail if the slug is empty after the slug.make function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "//"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		h := NewOrganizationController(nil, nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}
	})

}
