// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestOpenCycloneDXVexJSONSetsJSONContentType(t *testing.T) {
	artifactService := mocks.NewArtifactService(t)
	assetVersionService := mocks.NewAssetVersionService(t)

	artifactService.EXPECT().
		GatherVexInformation(mock.Anything, mock.Anything, mock.Anything).
		Return([]models.DependencyVuln{}, nil)
	assetVersionService.EXPECT().
		BuildOpenVeX(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(vex.New())

	controller := &ArtifactController{
		artifactService:     artifactService,
		assetVersionService: assetVersionService,
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/openvex.json", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	shared.SetAsset(ctx, models.Asset{})
	shared.SetAssetVersion(ctx, models.AssetVersion{})
	shared.SetOrg(ctx, models.Org{})
	shared.SetArtifact(ctx, models.Artifact{})

	require.NoError(t, controller.OpenCycloneDXVexJSON(ctx))

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}
