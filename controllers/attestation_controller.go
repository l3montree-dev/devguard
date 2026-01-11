package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type AttestationController struct {
	attestationRepository  shared.AttestationRepository
	assetVersionRepository shared.AssetVersionRepository
	artifactRepository     shared.ArtifactRepository
}

func NewAttestationController(repository shared.AttestationRepository, assetVersionRepository shared.AssetVersionRepository, artifactRepository shared.ArtifactRepository) *AttestationController {
	return &AttestationController{
		attestationRepository:  repository,
		assetVersionRepository: assetVersionRepository,
		artifactRepository:     artifactRepository,
	}
}

// @Summary List attestations
// @Tags Attestations
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {array} models.Attestation
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/attestations [get]
func (a *AttestationController) List(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	attestationList, err := a.attestationRepository.GetByAssetVersionAndAssetID(asset.GetID(), assetVersion.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

// @Summary Create attestation
// @Tags Attestations
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "Attestation content"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Artifact-Name header string false "Artifact name"
// @Param X-Predicate-Type header string false "Predicate type"
// @Success 200
// @Router /attestations [post]
func (a *AttestationController) Create(ctx shared.Context) error {

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
