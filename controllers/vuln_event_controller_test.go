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

package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestReadEventsByAssetIDAndAssetVersionName(t *testing.T) {
	t.Run("should return 500 if repository returns an error", func(t *testing.T) {
		mockRepo := mocks.NewVulnEventRepository(t)
		mockAssetVersionRepo := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		asset := models.Asset{}
		asset.ID = assetID

		assetVersion := models.AssetVersion{Name: "main"}

		mockRepo.On("ReadEventsByAssetIDAndAssetVersionName", mock.Anything, mock.Anything, assetID, "main", mock.Anything, mock.Anything).
			Return(shared.Paged[models.VulnEventDetail]{}, assert.AnError)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/events/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		shared.SetAsset(ctx, asset)
		shared.SetAssetVersion(ctx, assetVersion)

		err := NewVulnEventController(mockRepo, mockAssetVersionRepo).ReadEventsByAssetIDAndAssetVersionName(ctx)

		assert.NotNil(t, err)
		assert.Equal(t, 500, err.(*echo.HTTPError).Code)
	})

	t.Run("should return packageName and vulnerabilityName from joined fields", func(t *testing.T) {
		mockRepo := mocks.NewVulnEventRepository(t)
		mockAssetVersionRepo := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		asset := models.Asset{}
		asset.ID = assetID

		assetVersion := models.AssetVersion{Name: "main"}

		detail := models.VulnEventDetail{}
		detail.VulnEvent = models.VulnEvent{
			Type:   dtos.EventTypeDetected,
			UserID: "system",
		}
		detail.ComponentPurl = "pkg:npm/express@4.18.2"
		detail.CVEID = "CVE-2024-1234"

		paged := shared.NewPaged(shared.PageInfo{Page: 1, PageSize: 10}, 1, []models.VulnEventDetail{detail})
		mockRepo.On("ReadEventsByAssetIDAndAssetVersionName", mock.Anything, mock.Anything, assetID, "main", mock.Anything, mock.Anything).
			Return(paged, nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/events/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		shared.SetAsset(ctx, asset)
		shared.SetAssetVersion(ctx, assetVersion)

		err := NewVulnEventController(mockRepo, mockAssetVersionRepo).ReadEventsByAssetIDAndAssetVersionName(ctx)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data []map[string]interface{} `json:"data"`
		}
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Len(t, body.Data, 1)
		assert.Equal(t, "pkg:npm/express@4.18.2", body.Data[0]["packageName"])
		assert.Equal(t, "CVE-2024-1234", body.Data[0]["vulnerabilityName"])
	})
}

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
		err := NewVulnEventController(mockRepository, mocksAssetVersionRepository).ReadAssetEventsByVulnID(ctx)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 400, err.(*echo.HTTPError).Code)
	})

	t.Run("should return 500 if repository returns an error", func(t *testing.T) {
		mockRepository := mocks.NewVulnEventRepository(t)
		mockRepository.On("ReadAssetEventsByVulnID", mock.Anything, mock.Anything, uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"), dtos.VulnTypeDependencyVuln).Return(nil, assert.AnError)
		mocksAssetVersionRepository := mocks.NewAssetVersionRepository(t)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/vuln-events?dependencyVulnID=ffffffff-ffff-ffff-ffff-ffffffffffff", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("dependencyVulnID")
		ctx.SetParamValues("ffffffff-ffff-ffff-ffff-ffffffffffff")

		// Execution
		err := NewVulnEventController(mockRepository, mocksAssetVersionRepository).ReadAssetEventsByVulnID(ctx)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 500, err.(*echo.HTTPError).Code)
	})
}
