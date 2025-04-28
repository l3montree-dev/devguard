package attestation_test

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/attestation"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

func TestList(t *testing.T) {
	t.Run("everything works as expected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/webhook", bytes.NewBufferString(""))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		asset := models.Asset{}
		assetVersion := models.AssetVersion{}

		core.SetAsset(ctx, asset)
		core.SetAssetVersion(ctx, assetVersion)

		assetVersionNameRepository := mocks.NewAssetVersionRepository(t)
		attestationRepository := mocks.NewAttestationRepository(t)
		attestationRepository.On("GetByAssetVersionAndAssetID", mock.Anything, mock.Anything).Return([]models.Attestation{
			{AttestationName: "not ocol name"},
		}, nil)
		attestationController := attestation.NewAttestationController(attestationRepository, assetVersionNameRepository)
		result := attestationController.List(ctx)
		if result != nil {
			t.Fail()
		}

	})
	t.Run("getByAssetID returns an error so we should also receive an error", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/webhook", bytes.NewBufferString(""))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		asset := models.Asset{}
		assetVersion := models.AssetVersion{}

		core.SetAsset(ctx, asset)
		core.SetAssetVersion(ctx, assetVersion)

		assetVersionNameRepository := mocks.NewAssetVersionRepository(t)
		attestationRepository := mocks.NewAttestationRepository(t)
		attestationRepository.On("GetByAssetVersionAndAssetID", mock.Anything, mock.Anything).Return([]models.Attestation{}, fmt.Errorf("Something went wrong"))
		attestationController := attestation.NewAttestationController(attestationRepository, assetVersionNameRepository)

		result := attestationController.List(ctx)

		if result == nil {
			t.Fail()
		}

	})
}
