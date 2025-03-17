package attestation

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type attestationController struct {
	attestationRepository core.AttestationRepository
}

func NewAttestationController(repository core.AttestationRepository) *attestationController {
	return &attestationController{
		attestationRepository: repository,
	}
}
