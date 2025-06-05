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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestHttpControllerGetConfigFile(t *testing.T) {
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
