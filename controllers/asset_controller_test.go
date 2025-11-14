// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
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

package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHTTPControllerGetConfigFile(t *testing.T) {
	e := echo.New()

	t.Run("returns 200 with asset config file", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("config1")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		shared.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "project-config-content",
				},
			},
		})
		shared.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "asset-config-content",
				},
			},
		})

		controller := &AssetController{}

		err := controller.GetConfigFile(ctx)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "{\"value\":\"asset-config-content\"}\n", rec.Body.String())
	})

	t.Run("should return project config file if asset config file is not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("config1")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		shared.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "project-config-content",
				},
			},
		})
		shared.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{},
		})

		controller := &AssetController{}

		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "{\"value\":\"project-config-content\"}\n", rec.Body.String())
	})

	t.Run("should return organization config file if asset and project config files are not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("config-file")
		ctx.SetParamValues("config1")

		shared.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		shared.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{},
		})
		shared.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{},
		})

		controller := &AssetController{}

		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "{\"value\":\"organization-config-content\"}\n", rec.Body.String())
	})
}

func TestHTTPControllerMembers(t *testing.T) {
	e := echo.New()

	t.Run("returns members successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockAdminClient := mocks.NewAdminClient(t)

		userID := "user-123"
		mockRBAC.On("GetAllMembersOfAsset", assetID.String()).Return([]string{userID}, nil)

		identities := []client.Identity{
			{
				Id: userID,
				Traits: map[string]any{
					"name": map[string]any{
						"first": "Test",
						"last":  "User",
					},
				},
			},
		}

		mockAdminClient.On("ListUser", mock.Anything).Return(identities, nil)
		mockRBAC.On("GetAssetRole", userID, assetID.String()).Return(shared.RoleMember, nil)

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		shared.SetAuthAdminClient(ctx, mockAdminClient)

		controller := &AssetController{}
		err := controller.Members(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var users []dtos.UserDTO
		json.Unmarshal(rec.Body.Bytes(), &users) // nolint:errcheck
		assert.Len(t, users, 1)
		assert.Equal(t, "Test User", users[0].Name)
	})
}

func TestHTTPControllerInviteMembers(t *testing.T) {
	e := echo.New()

	t.Run("successfully invites members", func(t *testing.T) {
		reqBody := dtos.AssetInviteToAssetRequest{
			Ids: []string{"user-123", "user-456"},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		projectID := uuid.New()
		assetID := uuid.New()
		asset := models.Asset{
			Model:     models.Model{ID: assetID},
			ProjectID: projectID,
		}

		mockRBAC := mocks.NewAccessControl(t)

		// Mock getting project members
		mockRBAC.On("GetAllMembersOfProject", projectID.String()).Return([]string{"user-123", "user-456", "user-789"}, nil)

		// Mock granting roles
		mockRBAC.On("GrantRoleInAsset", "user-123", shared.RoleMember, assetID.String()).Return(nil)
		mockRBAC.On("GrantRoleInAsset", "user-456", shared.RoleMember, assetID.String()).Return(nil)

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user-123")
		shared.SetSession(ctx, session)
		controller := &AssetController{}
		err := controller.InviteMembers(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("returns error when user is not project member", func(t *testing.T) {
		reqBody := dtos.AssetInviteToAssetRequest{
			Ids: []string{"user-123"},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		projectID := uuid.New()
		assetID := uuid.New()
		asset := models.Asset{
			Model:     models.Model{ID: assetID},
			ProjectID: projectID,
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockRBAC.On("GetAllMembersOfProject", projectID.String()).Return([]string{"user-789"}, nil)

		session := mocks.NewAuthSession(t)
		// 	session.On("GetUserID").Return("user-000")

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		shared.SetSession(ctx, session)

		controller := &AssetController{}
		err := controller.InviteMembers(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "not a member of the asset")
	})

	t.Run("returns error when RBAC fails", func(t *testing.T) {
		reqBody := dtos.AssetInviteToAssetRequest{
			Ids: []string{"user-123"},
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		projectID := uuid.New()
		assetID := uuid.New()
		asset := models.Asset{
			Model:     models.Model{ID: assetID},
			ProjectID: projectID,
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockRBAC.On("GetAllMembersOfProject", projectID.String()).Return([]string{}, errors.New("rbac error"))

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)

		controller := &AssetController{}
		err := controller.InviteMembers(ctx)

		assert.Error(t, err)
	})
}

func TestHTTPControllerRemoveMember(t *testing.T) {
	e := echo.New()

	t.Run("successfully removes member", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("userID")
		ctx.SetParamValues("user-123")

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockRBAC.On("RevokeRoleInAsset", "user-123", shared.RoleAdmin, assetID.String()).Return(nil)
		mockRBAC.On("RevokeRoleInAsset", "user-123", shared.RoleMember, assetID.String()).Return(nil)

		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user-123")
		shared.SetSession(ctx, session)
		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)

		controller := &AssetController{}
		err := controller.RemoveMember(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("returns error when userID is missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)

		controller := &AssetController{}
		err := controller.RemoveMember(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("removes member even when revoke fails (nolint)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("userID")
		ctx.SetParamValues("user-123")

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		// Even if revoke fails, the function should succeed (as per nolint comment)
		mockRBAC.On("RevokeRoleInAsset", "user-123", shared.RoleAdmin, assetID.String()).Return(errors.New("not an admin"))
		mockRBAC.On("RevokeRoleInAsset", "user-123", shared.RoleMember, assetID.String()).Return(errors.New("not a member"))

		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user-123")
		shared.SetSession(ctx, session)
		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)

		controller := &AssetController{}
		err := controller.RemoveMember(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
