package attestation

import (
	"encoding/json"
	"io"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type attestationController struct {
	attestationRepository core.AttestationRepository
}

func NewAttestationController(repository core.AttestationRepository) *attestationController {
	return &attestationController{
		attestationRepository: repository,
	}
}

func (a *attestationController) List(ctx core.Context) error {

	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)

	attestationList, err := a.attestationRepository.GetByAssetVersion(asset.GetID(), assetVersion.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

func (a *attestationController) Create(ctx core.Context) error {
	var attestation models.Attestation
	jsonContent := make(map[string]any)

	assetVersion := core.GetAssetVersion(ctx)
	attestation.AssetID = core.GetAsset(ctx).ID

	attestation.AssetVersionName = assetVersion.Name
	attestation.AssetVersion = assetVersion
	attestation.AttestationName = ctx.Request().Header.Get("X-Attestation-Name")

	content, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, "unable to bind data to attestation model").WithInternal(err)
	}

	err = json.Unmarshal(content, &jsonContent) //convert the byte array from io.ReadAll into a readable json
	if err != nil {
		return err
	}

	err = core.V.Struct(attestation)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	err = a.attestationRepository.Create(nil, &attestation)
	if err != nil {
		return err
	}

	return nil
}
