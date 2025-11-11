package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type attestationController struct {
	attestationRepository  shared.AttestationRepository
	assetVersionRepository shared.AssetVersionRepository
	artifactRepository     shared.ArtifactRepository
}

func NewAttestationController(repository shared.AttestationRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository) *attestationController {
	return &attestationController{
		attestationRepository:  repository,
		assetVersionRepository: assetVersionRepository,
		artifactRepository:     artifactRepository,
	}
}

func (a *attestationController) List(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	attestationList, err := a.attestationRepository.GetByAssetVersionAndAssetID(asset.GetID(), assetVersion.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

func (a *attestationController) Create(ctx shared.Context) error {

	jsonContent := make(map[string]any)

	asset := shared.GetAsset(ctx)

	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	artifactName := ctx.Request().Header.Get("X-Artifact-Name")
	if artifactName == "" {
		artifactName = "default"
	}
	// check if the artifact exists
	_, err := a.artifactRepository.ReadArtifact(artifactName, assetVersionName, asset.ID)
	if err != nil {
		return echo.NewHTTPError(400, "artifact does not exist").WithInternal(err)
	}

	attestation := models.Attestation{
		AssetID:          asset.ID,
		AssetVersionName: assetVersionName,
		ArtifactName:     artifactName,
		PredicateType:    ctx.Request().Header.Get("X-Predicate-Type"),
	}

	content, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, "unable to bind data to attestation model").WithInternal(err)
	}

	err = json.Unmarshal(content, &jsonContent) //convert the byte array from io.ReadAll into a readable json
	if err != nil {
		return err
	}

	err = shared.V.Struct(attestation)
	if err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}
	attestation.Content = jsonContent
	err = a.attestationRepository.Create(nil, &attestation)
	if err != nil {
		return err
	}

	return nil
}
