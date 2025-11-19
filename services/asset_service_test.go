// Copyright (C) 2025 l3montree GmbH
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
package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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
		mockRBAC.On("GetAssetRole", userID1, assetID.String()).Return(shared.RoleMember, nil)
		mockRBAC.On("GetAssetRole", userID2, assetID.String()).Return(shared.RoleAdmin, nil)

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		shared.SetAuthAdminClient(ctx, mockAdminClient)

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

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)

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

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		shared.SetAuthAdminClient(ctx, mockAdminClient)

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
		mockRBAC.On("GetAssetRole", userID1, assetID.String()).Return(shared.RoleMember, nil)

		shared.SetAsset(ctx, asset)
		shared.SetRBAC(ctx, mockRBAC)
		shared.SetAuthAdminClient(ctx, mockAdminClient)

		users, err := FetchMembersOfAsset(ctx)

		assert.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "", users[0].Name)
	})
}
