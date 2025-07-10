package vuln

import (
	"encoding/json"
	"log/slog"
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
	licenseRiskRepository core.LicenseRiskRepository
	licenseRiskService    core.LicenseRiskService
}

type LicenseRiskStatus struct {
	StatusType              string                             `json:"status"`
	Justification           string                             `json:"justification"`
	MechanicalJustification models.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewLicenseRiskController(licenseOverwriteRepository core.LicenseRiskRepository, LicenseRiskService core.LicenseRiskService) *LicenseRiskController {
	return &LicenseRiskController{
		licenseRiskRepository: licenseOverwriteRepository,
		licenseRiskService:    LicenseRiskService,
	}
}

func (controller LicenseRiskController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	pagedResp, err := controller.licenseRiskRepository.GetAllLicenseRisksForAssetVersionPaged(
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
	result, err = controller.licenseRiskRepository.MaybeGetLicenseOverwriteForComponent(assetID, assetVersionName, validPURL)
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
	err := controller.licenseRiskRepository.Save(nil, &newLicenseRisk)
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

	err = controller.licenseRiskRepository.DeleteByComponentPurl(assetVersion.AssetID, assetVersion.Name, parsedPURL)
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

func (controller LicenseRiskController) Read(ctx core.Context) error {
	licenseRiskID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "could not get license risk ID")
	}
	licenseRisk, err := controller.licenseRiskRepository.Read(licenseRiskID)
	if err != nil {
		return echo.NewHTTPError(404, "could fetch data from the database")
	}
	return ctx.JSON(200, convertLicenseRiskToDetailedDTO(licenseRisk))
}

func (controller LicenseRiskController) Mitigate(ctx core.Context) error {
	var justification struct {
		Comment string `json:"comment"`
	}

	err := ctx.Bind(&justification)
	if err != nil {
		return echo.NewHTTPError(500, "could not bind the request to a justification")
	}

	licenseRiskID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid licenseRisk id")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Ctx:           ctx,
		Justification: justification.Comment,
	})
	if err != nil {
		return echo.NewHTTPError(500, "could not mitigate licenseRisk").WithInternal(err)
	}

	licenseRisk, err := controller.licenseRiskRepository.Read(licenseRiskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find licenseRisk")
	}
	return ctx.JSON(200, convertLicenseRiskToDetailedDTO(licenseRisk))
}

func (controller LicenseRiskController) CreateEvent(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	licenseRiskID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid licenseRisk id")
	}

	licenseRisk, err := controller.licenseRiskRepository.Read(licenseRiskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find licenseRisk")
	}
	userID := core.GetSession(ctx).GetUserID()

	var status LicenseRiskStatus
	err = json.NewDecoder(ctx.Request().Body).Decode(&status)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	statusType := status.StatusType
	err = models.CheckStatusType(statusType)
	if err != nil {
		return echo.NewHTTPError(400, "invalid status type")
	}
	justification := status.Justification
	mechanicalJustification := status.MechanicalJustification

	event, err := controller.licenseRiskService.UpdateLicenseRiskState(nil, userID, &licenseRisk, statusType, justification, mechanicalJustification)
	if err != nil {
		return err
	}
	err = thirdPartyIntegration.HandleEvent(core.VulnEvent{
		Ctx:   ctx,
		Event: event,
	})
	// we do not want the transaction to be rolled back if the third party integration fails
	if err != nil {
		// just log the error
		slog.Error("could not handle event", "err", err)
		return echo.NewHTTPError(500, "could not create licenseRisk event").WithInternal(err)
	}
	return ctx.JSON(200, convertLicenseRiskToDetailedDTO(licenseRisk))
}
