package component

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
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

func (controller LicenseOverwriteController) Create(ctx core.Context) error {
	var newLicenseOverwrite models.LicenseOverwrite
	if err := ctx.Bind(&newLicenseOverwrite); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(newLicenseOverwrite); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if newLicenseOverwrite.License_id == "" {
		return echo.NewHTTPError(400, "license id must not be empty")
	}
	err := controller.LicenseOverwriteRepository.Create(nil, &newLicenseOverwrite)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}
	return ctx.JSON(200, newLicenseOverwrite)
}
