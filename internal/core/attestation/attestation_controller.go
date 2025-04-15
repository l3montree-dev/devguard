package attestation

import (
	"fmt"
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

	attestationList, err := a.attestationRepository.GetByAssetID(asset.GetID())
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

func (a *attestationController) Create(ctx core.Context) error {
	var attestation models.Attestation

	assetVersion := core.GetAssetVersion(ctx)

	attestation.AssetID = core.GetAsset(ctx).ID

	attestation.AssetVersionName = assetVersion.Name
	attestation.AssetVersion = assetVersion
	//How to get the name of the attestation ?

	content, err := io.ReadAll(ctx.Request().Body)

	if err != nil {
		return echo.NewHTTPError(400, "unable to bind data to attestation model").WithInternal(err)
	}
	//json := make(map[string]string)
	//err = json.Unmarshal(content, &json)
	fmt.Printf("content: %s \n", content)

	err = core.V.Struct(attestation)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	return nil

}
