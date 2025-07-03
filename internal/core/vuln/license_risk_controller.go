package vuln

import (
	"net/url"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
)

type LicenseRiskController struct {
	LicenseRiskRepository core.LicenseRiskRepository
}

func NewLicenseRiskController(licenseOverwriteRepository core.LicenseRiskRepository) *LicenseRiskController {
	return &LicenseRiskController{
		LicenseRiskRepository: licenseOverwriteRepository,
	}
}

func (controller LicenseRiskController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	pagedResp, err := controller.LicenseRiskRepository.GetAllLicenseRisksForAssetVersionPaged(
		nil,
		assetVersion.AssetID,
		assetVersion.Name,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get license risks").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(licenseRisk models.LicenseRisk) any {
		return convertLicenseRiskToDetailedDTO(licenseRisk)
	}))

}

func (controller LicenseRiskController) GetComponentOverwriteForAssetVersion(assetID uuid.UUID, assetVersionName string, pURL string) (models.LicenseRisk, error) {
	var result models.LicenseRisk
	validPURL, err := packageurl.FromString(pURL)
	if err != nil {
		return result, err
	}
	result, err = controller.LicenseRiskRepository.MaybeGetLicenseOverwriteForComponent(assetID, assetVersionName, validPURL)
	if err != nil {
		return result, err
	}
	return result, nil
}

func (controller LicenseRiskController) Create(ctx core.Context) error {
	var newLicenseRisk models.LicenseRisk
	if err := ctx.Bind(&newLicenseRisk); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(newLicenseRisk); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if newLicenseRisk.FinalLicenseDecision == "" {
		return echo.NewHTTPError(400, "license id must not be empty")
	}
	err := controller.LicenseRiskRepository.Save(nil, &newLicenseRisk)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}
	return ctx.JSON(200, newLicenseRisk)
}

func (controller LicenseRiskController) Delete(ctx core.Context) error {
	componentPurl := ctx.Param("componentPurl")
	assetVersion := core.GetAssetVersion(ctx)
	if componentPurl == "" {
		return echo.NewHTTPError(400, "could not retrieve a valid component purl")
	}
	// url decode
	componentPurl, err := url.PathUnescape(componentPurl)
	if err != nil {
		return echo.NewHTTPError(400, "invalid component purl").WithInternal(err)
	}
	// validate package url
	parsedPURL, err := packageurl.FromString(componentPurl)
	if err != nil {
		return echo.NewHTTPError(400, "invalid component purl").WithInternal(err)
	}

	err = controller.LicenseRiskRepository.DeleteByComponentPurl(assetVersion.AssetID, assetVersion.Name, parsedPURL)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}
	return ctx.NoContent(200)
}

func convertLicenseRiskToDetailedDTO(licenseRisk models.LicenseRisk) detailedLicenseRiskDTO {
	return detailedLicenseRiskDTO{
		LicenseRiskDTO: LicenseRiskToDto(licenseRisk),
		Events: utils.Map(licenseRisk.Events, func(ev models.VulnEvent) events.VulnEventDTO {
			return events.VulnEventDTO{
				ID:                      ev.ID,
				Type:                    ev.Type,
				VulnID:                  ev.VulnID,
				UserID:                  ev.UserID,
				Justification:           ev.Justification,
				MechanicalJustification: ev.MechanicalJustification,
				AssetVersionName:        licenseRisk.AssetVersionName,
				VulnerabilityName:       licenseRisk.ComponentPurl,
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
			}
		}),
	}
}
