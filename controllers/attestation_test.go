package controllers

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
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

		shared.SetAsset(ctx, asset)
		shared.SetAssetVersion(ctx, assetVersion)

		attestationRepository := mocks.NewAttestationRepository(t)
		attestationRepository.On("GetByAssetVersionAndAssetID", mock.Anything, mock.Anything).Return([]models.Attestation{
			{PredicateType: "not ocol name"},
		}, nil)

		attestationController := NewAttestationController(attestationRepository, mocks.NewArtifactRepository(t))
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

		shared.SetAsset(ctx, asset)
		shared.SetAssetVersion(ctx, assetVersion)

		attestationRepository := mocks.NewAttestationRepository(t)
		attestationRepository.On("GetByAssetVersionAndAssetID", mock.Anything, mock.Anything).Return([]models.Attestation{}, fmt.Errorf("Something went wrong"))
		attestationController := NewAttestationController(attestationRepository, mocks.NewArtifactRepository(t))

		result := attestationController.List(ctx)

		if result == nil {
			t.Fail()
		}

	})
}
