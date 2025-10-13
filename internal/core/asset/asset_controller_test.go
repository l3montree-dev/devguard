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

package asset

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
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

		core.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		core.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "project-config-content",
				},
			},
		})
		core.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "asset-config-content",
				},
			},
		})

		controller := &httpController{}

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

		core.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		core.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "project-config-content",
				},
			},
		})
		core.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{},
		})

		controller := &httpController{}

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

		core.SetOrg(ctx, models.Org{
			ConfigFiles: map[string]any{
				"config1": map[string]any{
					"value": "organization-config-content",
				},
			},
		})
		core.SetProject(ctx, models.Project{
			ConfigFiles: map[string]any{},
		})
		core.SetAsset(ctx, models.Asset{
			ConfigFiles: map[string]any{},
		})

		controller := &httpController{}

		err := controller.GetConfigFile(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "{\"value\":\"organization-config-content\"}\n", rec.Body.String())
	})
}

func TestFetchMembersOfAsset(t *testing.T) {
	e := echo.New()

	t.Run("successfully fetches members with roles", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockAdminClient := mocks.NewAdminClient(t)

		userID1 := "user-123"
		userID2 := "user-456"

		// Mock RBAC to return members
		mockRBAC.On("GetAllMembersOfAsset", assetID.String()).Return([]string{userID1, userID2}, nil)

		// Mock admin client to return user identities
		identities := []client.Identity{
			{
				Id: userID1,
				Traits: map[string]any{
					"name": map[string]any{
						"first": "John",
						"last":  "Doe",
					},
				},
			},
			{
				Id: userID2,
				Traits: map[string]any{
					"name": map[string]any{
						"first": "Jane",
						"last":  "Smith",
					},
				},
			},
		}

		mockAdminClient.On("ListUser", mock.MatchedBy(func(req client.IdentityAPIListIdentitiesRequest) bool {
			return true
		})).Return(identities, nil)

		// Mock RBAC to return roles
		mockRBAC.On("GetAssetRole", userID1, assetID.String()).Return(core.RoleMember, nil)
		mockRBAC.On("GetAssetRole", userID2, assetID.String()).Return(core.RoleAdmin, nil)

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)
		core.SetAuthAdminClient(ctx, mockAdminClient)

		users, err := FetchMembersOfAsset(ctx)

		assert.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, "John Doe", users[0].Name)
		assert.Equal(t, "member", users[0].Role)
		assert.Equal(t, "Jane Smith", users[1].Name)
		assert.Equal(t, "admin", users[1].Role)
	})

	t.Run("returns error when RBAC fails to get members", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockRBAC.On("GetAllMembersOfAsset", assetID.String()).Return([]string{}, errors.New("rbac error"))

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		users, err := FetchMembersOfAsset(ctx)

		assert.Error(t, err)
		assert.Nil(t, users)
	})

	t.Run("returns error when admin client fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockAdminClient := mocks.NewAdminClient(t)

		mockRBAC.On("GetAllMembersOfAsset", assetID.String()).Return([]string{"user-123"}, nil)
		mockAdminClient.On("ListUser", mock.Anything).Return([]client.Identity{}, errors.New("auth service error"))

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)
		core.SetAuthAdminClient(ctx, mockAdminClient)

		users, err := FetchMembersOfAsset(ctx)

		assert.Error(t, err)
		assert.Nil(t, users)
	})

	t.Run("handles missing name fields gracefully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
		}

		mockRBAC := mocks.NewAccessControl(t)
		mockAdminClient := mocks.NewAdminClient(t)

		userID1 := "user-123"

		mockRBAC.On("GetAllMembersOfAsset", assetID.String()).Return([]string{userID1}, nil)

		identities := []client.Identity{
			{
				Id: userID1,
				Traits: map[string]any{
					"name": map[string]any{},
				},
			},
		}

		mockAdminClient.On("ListUser", mock.Anything).Return(identities, nil)
		mockRBAC.On("GetAssetRole", userID1, assetID.String()).Return(core.RoleMember, nil)

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)
		core.SetAuthAdminClient(ctx, mockAdminClient)

		users, err := FetchMembersOfAsset(ctx)

		assert.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "", users[0].Name)
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
		mockRBAC.On("GetAssetRole", userID, assetID.String()).Return(core.RoleMember, nil)

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)
		core.SetAuthAdminClient(ctx, mockAdminClient)

		controller := &httpController{}
		err := controller.Members(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var users []core.User
		json.Unmarshal(rec.Body.Bytes(), &users) // nolint:errcheck
		assert.Len(t, users, 1)
		assert.Equal(t, "Test User", users[0].Name)
	})
}

func TestHTTPControllerInviteMembers(t *testing.T) {
	e := echo.New()

	t.Run("successfully invites members", func(t *testing.T) {
		reqBody := inviteToAssetRequest{
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
		mockRBAC.On("GrantRoleInAsset", "user-123", core.RoleMember, assetID.String()).Return(nil)
		mockRBAC.On("GrantRoleInAsset", "user-456", core.RoleMember, assetID.String()).Return(nil)

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
		err := controller.InviteMembers(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("returns error when user is not project member", func(t *testing.T) {
		reqBody := inviteToAssetRequest{
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

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
		err := controller.InviteMembers(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "not a member of the organization")
	})

	t.Run("returns error when RBAC fails", func(t *testing.T) {
		reqBody := inviteToAssetRequest{
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

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
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
		mockRBAC.On("RevokeRoleInAsset", "user-123", core.RoleAdmin, assetID.String()).Return(nil)
		mockRBAC.On("RevokeRoleInAsset", "user-123", core.RoleMember, assetID.String()).Return(nil)

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
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
		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
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
		mockRBAC.On("RevokeRoleInAsset", "user-123", core.RoleAdmin, assetID.String()).Return(errors.New("not an admin"))
		mockRBAC.On("RevokeRoleInAsset", "user-123", core.RoleMember, assetID.String()).Return(errors.New("not a member"))

		core.SetAsset(ctx, asset)
		core.SetRBAC(ctx, mockRBAC)

		controller := &httpController{}
		err := controller.RemoveMember(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
