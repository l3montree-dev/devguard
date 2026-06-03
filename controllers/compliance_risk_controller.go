package controllers

import (
	"encoding/json"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ComplianceRiskController struct {
	complianceRiskRepository shared.ComplianceRiskRepository
	complianceRiskService    shared.ComplianceRiskService
}

func NewComplianceRiskController(repo shared.ComplianceRiskRepository, svc shared.ComplianceRiskService) *ComplianceRiskController {
	return &ComplianceRiskController{
		complianceRiskRepository: repo,
		complianceRiskService:    svc,
	}
}

type complianceRiskStatus struct {
	StatusType              string                           `json:"status"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
}

func convertComplianceRiskToDetailedDTO(r models.ComplianceRisk) dtos.DetailedComplianceRiskDTO {
	return dtos.DetailedComplianceRiskDTO{
		ComplianceRiskDTO: transformer.ComplianceRiskToDTO(r),
		Events: utils.Map(r.Events, func(ev models.VulnEvent) dtos.VulnEventDTO {
			return dtos.VulnEventDTO{
				ID:                       ev.ID,
				Type:                     ev.Type,
				VulnID:                   ev.GetVulnID(),
				UserID:                   ev.UserID,
				Justification:            ev.Justification,
				MechanicalJustification:  ev.MechanicalJustification,
				OriginalAssetVersionName: ev.OriginalAssetVersionName,
				VulnerabilityName:        r.PolicyID,
				ArbitraryJSONData:        ev.GetArbitraryJSONData(),
				CreatedAt:                ev.CreatedAt,
				CreatedByVexRule:         ev.CreatedByVexRule,
			}
		}),
	}
}

func (c *ComplianceRiskController) ListPaged(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	pagedResp, err := c.complianceRiskRepository.GetAllComplianceRisksForAssetVersionPaged(
		ctx.Request().Context(), nil,
		assetVersion.AssetID,
		assetVersion.Name,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get compliance risks").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(r models.ComplianceRisk) any {
		return convertComplianceRiskToDetailedDTO(r)
	}))
}

func (c *ComplianceRiskController) Read(ctx shared.Context) error {
	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "could not get compliance risk ID")
	}
	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}
	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}

func (c *ComplianceRiskController) CreateEvent(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid compliance risk id")
	}

	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}

	var status complianceRiskStatus
	if err := json.NewDecoder(ctx.Request().Body).Decode(&status); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}
	if err := models.CheckStatusType(status.StatusType); err != nil {
		return echo.NewHTTPError(400, "invalid status type")
	}

	userID := shared.GetSession(ctx).GetUserID()
	userAgent := ctx.Request().UserAgent()

	event, err := c.complianceRiskService.UpdateComplianceRiskState(ctx.Request().Context(), nil, userID, &risk, status.StatusType, status.Justification, status.MechanicalJustification, &userAgent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create compliance risk event").WithInternal(err)
	}

	if err := thirdPartyIntegration.HandleEvent(ctx.Request().Context(), shared.VulnEvent{
		Ctx:   ctx,
		Event: event,
	}, &userAgent); err != nil {
		slog.Error("could not handle third-party event for compliance risk", "err", err)
		return echo.NewHTTPError(500, "could not create compliance risk event").WithInternal(err)
	}

	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}

func (c *ComplianceRiskController) Mitigate(ctx shared.Context) error {
	var justification struct {
		Comment string `json:"comment"`
	}
	if err := ctx.Bind(&justification); err != nil {
		return echo.NewHTTPError(500, "could not bind the request to a justification")
	}

	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid compliance risk id")
	}

	userAgent := ctx.Request().UserAgent()
	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)

	if err := thirdPartyIntegrations.HandleEvent(ctx.Request().Context(), shared.ManualMitigateEvent{
		Ctx:           ctx,
		Justification: justification.Comment,
	}, &userAgent); err != nil {
		return echo.NewHTTPError(500, "could not mitigate compliance risk").WithInternal(err)
	}

	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}
	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}
