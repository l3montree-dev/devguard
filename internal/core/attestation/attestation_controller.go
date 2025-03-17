package attestation

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type attestationController struct {
	attestationRepository core.AttestationRepository
}

func (a *attestationController) List(ctx core.Context) error {

	asset := core.GetAsset(ctx)

	attestationList, err := a.attestationRepository.GetByAssetID(asset.GetID())
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

func NewAttestationController(repository core.AttestationRepository) *attestationController {
	return &attestationController{
		attestationRepository: repository,
	}
}

func (a *attestationController) Create()
