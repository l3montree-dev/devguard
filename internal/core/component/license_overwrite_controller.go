package component

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
)

type LicenseOverwriteController struct {
	LicenseOverwriteRepository core.LicenseOverwriteRepository
}

func NewLicenseOverwriteController(licenseOverwriteRepository core.LicenseOverwriteRepository) *LicenseOverwriteController {
	return &LicenseOverwriteController{
		LicenseOverwriteRepository: licenseOverwriteRepository,
	}
}

func (controller LicenseOverwriteController) GetComponentOverwriteForOrganization(org_id uuid.UUID, pURL string) (models.LicenseOverwrite, error) {
	var result models.LicenseOverwrite
	valid_purl, err := packageurl.FromString(pURL)
	if err != nil {
		return result, err
	}
	result, err = controller.LicenseOverwriteRepository.MaybeGetOverwriteForComponent(org_id, valid_purl)
	if err != nil {
		return result, err
	}
	return result, nil
}
