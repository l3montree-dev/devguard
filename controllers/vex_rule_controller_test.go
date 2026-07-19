// Copyright (C) 2026 l3montree GmbH
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestVEXRuleControllerReapplyFindErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		findError  error
		statusCode int
	}{
		{
			name:       "returns not found only for a missing rule",
			findError:  gorm.ErrRecordNotFound,
			statusCode: http.StatusNotFound,
		},
		{
			name:       "returns internal server error for repository failures",
			findError:  assert.AnError,
			statusCode: http.StatusInternalServerError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			vexRuleService := mocks.NewVEXRuleService(t)
			vexRuleService.On("FindByID", mock.Anything, mock.Anything, "rule-id").
				Return(models.VEXRule{}, test.findError)

			e := echo.New()
			ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/vex-rules/rule-id/reapply", nil), httptest.NewRecorder())
			ctx.SetParamNames("ruleId")
			ctx.SetParamValues("rule-id")
			shared.SetAsset(ctx, models.Asset{Model: models.Model{ID: uuid.New()}})
			shared.SetAssetVersion(ctx, models.AssetVersion{Name: "main"})

			err := NewVEXRuleController(vexRuleService, nil, nil).Reapply(ctx)

			var httpError *echo.HTTPError
			if assert.ErrorAs(t, err, &httpError) {
				assert.Equal(t, test.statusCode, httpError.Code)
			}
		})
	}
}
