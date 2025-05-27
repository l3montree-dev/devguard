package component

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type LicenseOverwriteController struct {
	LicenseOverwriteRepository core.LicenseOverwriteRepository
}

func NewLicenseOverwriteController(licenseOverwriteRepository core.LicenseOverwriteRepository) *LicenseOverwriteController {
	return &LicenseOverwriteController{
		LicenseOverwriteRepository: licenseOverwriteRepository,
	}
}
