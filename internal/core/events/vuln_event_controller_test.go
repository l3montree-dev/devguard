// Copyright (C) 2025 timbastin
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

package events_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestReadAssetEventsByVulnID(t *testing.T) {
	t.Run("should return 400 if vulnID is missing", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/vuln-events", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRepository := mocks.NewVulnEventRepository(t)
		mocksAssetVersionRepository := mocks.NewAssetVersionRepository(t)
		// Execution
		err := events.NewVulnEventController(mockRepository, mocksAssetVersionRepository).ReadAssetEventsByVulnID(ctx)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 400, err.(*echo.HTTPError).Code)
	})

	t.Run("should return 500 if repository returns an error", func(t *testing.T) {
		mockRepository := mocks.NewVulnEventRepository(t)
		mockRepository.On("ReadAssetEventsByVulnID", "vulnID", models.VulnTypeDependencyVuln).Return(nil, assert.AnError)
		mocksAssetVersionRepository := mocks.NewAssetVersionRepository(t)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/vuln-events?vulnID=vulnID", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("dependencyVulnID")
		ctx.SetParamValues("vulnID")

		// Execution
		err := events.NewVulnEventController(mockRepository, mocksAssetVersionRepository).ReadAssetEventsByVulnID(ctx)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 500, err.(*echo.HTTPError).Code)
	})
}
