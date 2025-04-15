package attestation

import (
	"fmt"
	"io/ioutil"

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

	content, err := ioutil.ReadAll(ctx.Request().Body)

	if err != nil {
		return echo.NewHTTPError(400, "unable to bind data to attestation model").WithInternal(err)
	}
	fmt.Printf("This is the content as string: %s\n", content)

	err = core.V.Struct(attestation)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	return nil

}
