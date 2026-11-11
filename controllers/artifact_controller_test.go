package controllers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOpenCycloneDXVexJSON(t *testing.T) {
	t.Run("the openvex document is served as json", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/openvex.json", bytes.NewBufferString(""))
		e := echo.New()
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(req, recorder)

		shared.SetAsset(ctx, models.Asset{})
		shared.SetAssetVersion(ctx, models.AssetVersion{})
		shared.SetArtifact(ctx, models.Artifact{})
		shared.SetOrg(ctx, models.Org{})

		artifactService := mocks.NewArtifactService(t)
		artifactService.On("GatherVexInformation", mock.Anything, mock.Anything, mock.Anything).Return([]models.DependencyVuln{}, nil)

		assetVersionService := mocks.NewAssetVersionService(t)
		assetVersionService.On("BuildOpenVeX", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(vex.New())

		artifactController := NewArtifactController(
			mocks.NewArtifactRepository(t),
			artifactService,
			assetVersionService,
			mocks.NewDependencyVulnService(t),
			mocks.NewStatisticsRepository(t),
			mocks.NewStatisticsService(t),
			mocks.NewScanService(t),
			&utils.GoroutineFireAndForgetSynchronizer{},
			mocks.NewDependencyVulnRepository(t),
			mocks.NewCSAFService(t),
			mocks.NewBroker(t),
		)

		err := artifactController.OpenCycloneDXVexJSON(ctx)

		assert.NoError(t, err)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.True(t, json.Valid(recorder.Body.Bytes()))
	})
}
