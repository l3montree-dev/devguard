package flaw

import (
	"encoding/json"
	"slices"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type FlawsByPackage struct {
	PackageName string    `json:"packageName"`
	AvgRisk     float64   `json:"avgRisk"`
	MaxRisk     float64   `json:"maxRisk"`
	FlawCount   int       `json:"flawCount"`
	TotalRisk   float64   `json:"totalRisk"`
	Flaws       []FlawDTO `json:"flaws"`
}

type repository interface {
	repositories.Repository[string, models.Flaw, core.DB]

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]models.Flaw, error)
	GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], map[string]int, error)
}
type flawService interface {
	UpdateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification *string) error
}

type flawHttpController struct {
	flawRepository repository
	flawService    flawService
}

type FlawStatus struct {
	StatusType    string `json:"status"`
	Justification string `json:"justification"`
}

func NewHttpController(flawRepository repository, flawService flawService) *flawHttpController {
	return &flawHttpController{
		flawRepository: flawRepository,
		flawService:    flawService,
	}
}

func (c flawHttpController) ListPaged(ctx core.Context) error {
	// get the asset
	asset := core.GetAsset(ctx)
	pagedResp, packageNameIndexMap, err := c.flawRepository.GetByAssetIdPaged(
		nil,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
		asset.GetID(),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	res := map[string]FlawsByPackage{}
	for _, flaw := range pagedResp.Data {
		// get the package name
		if _, ok := res[flaw.ComponentPurl]; !ok {
			res[flaw.ComponentPurl] = FlawsByPackage{
				PackageName: flaw.ComponentPurl,
			}
		}
		flawsByPackage := res[flaw.ComponentPurl]
		// append the flaw to the package
		flawsByPackage.Flaws = append(res[flaw.ComponentPurl].Flaws, FlawDTO{
			ID:                flaw.ID,
			ScannerID:         flaw.ScannerID,
			Message:           flaw.Message,
			AssetID:           flaw.AssetID.String(),
			State:             flaw.State,
			CVE:               flaw.CVE,
			Component:         flaw.Component,
			CVEID:             flaw.CVEID,
			ComponentPurl:     flaw.ComponentPurl,
			Effort:            flaw.Effort,
			RiskAssessment:    flaw.RiskAssessment,
			RawRiskAssessment: flaw.RawRiskAssessment,
			Priority:          flaw.Priority,
			ArbitraryJsonData: flaw.GetArbitraryJsonData(),
			LastDetected:      flaw.LastDetected,
			CreatedAt:         flaw.CreatedAt,
		})
		res[flaw.ComponentPurl] = flawsByPackage
	}

	values := make([]FlawsByPackage, 0, len(res))
	for _, v := range res {
		// calculate the max and average risk
		maxRisk := 0.
		totalRisk := 0.

		for _, f := range v.Flaws {
			totalRisk += utils.OrDefault(f.RawRiskAssessment, 0)
			if utils.OrDefault(f.RawRiskAssessment, 0) > maxRisk {
				maxRisk = *f.RawRiskAssessment
			}
		}
		v.AvgRisk = totalRisk / float64(len(v.Flaws))
		v.MaxRisk = maxRisk
		v.TotalRisk = totalRisk
		v.FlawCount = len(v.Flaws)
		values = append(values, v)
	}

	// sort the value based on the index map
	slices.SortFunc(values, func(a, b FlawsByPackage) int {
		return packageNameIndexMap[a.PackageName] - packageNameIndexMap[b.PackageName]
	})

	return ctx.JSON(200, core.NewPaged(core.GetPageInfo(ctx), pagedResp.Total, values))
}

func (c flawHttpController) Mitigate(ctx core.Context) error {
	flawId, err := core.GetFlawID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid flaw id")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	if err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Ctx: ctx,
	}); err != nil {
		return echo.NewHTTPError(500, "could not mitigate flaw").WithInternal(err)
	}

	// fetch the flaw again from the database. We do not know anything what might have changed. The third party integrations might have changed the state of the flaw.
	flaw, err := c.flawRepository.Read(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	return ctx.JSON(200, convertToDetailedDTO(flaw))
}

func (c flawHttpController) Read(ctx core.Context) error {
	flawId, err := core.GetFlawID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid flaw id")
	}
	asset := core.GetAsset(ctx)

	flaw, err := c.flawRepository.Read(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	risk, vector := risk.RiskCalculation(*flaw.CVE, core.GetEnvironmentalFromAsset(asset))
	flaw.CVE.Risk = risk
	flaw.CVE.Vector = vector

	return ctx.JSON(200, convertToDetailedDTO(flaw))
}

func (c flawHttpController) CreateEvent(ctx core.Context) error {

	flawId, err := core.GetFlawID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid flaw id")
	}

	flaw, err := c.flawRepository.Read(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}
	userID := core.GetSession(ctx).GetUserID()

	var status FlawStatus
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

	err = c.flawRepository.Transaction(func(tx core.DB) error {
		return c.flawService.UpdateFlawState(tx, userID, &flaw, statusType, &justification)
	})
	if err != nil {
		return echo.NewHTTPError(500, "could not create flaw event").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(flaw))
}

func convertToDetailedDTO(flaw models.Flaw) detailedFlawDTO {
	return detailedFlawDTO{
		FlawDTO: FlawDTO{
			ID:                flaw.ID,
			Message:           flaw.Message,
			AssetID:           flaw.AssetID.String(),
			State:             flaw.State,
			CVE:               flaw.CVE,
			Component:         flaw.Component,
			CVEID:             flaw.CVEID,
			ComponentPurl:     flaw.ComponentPurl,
			Effort:            flaw.Effort,
			RiskAssessment:    flaw.RiskAssessment,
			RawRiskAssessment: flaw.RawRiskAssessment,
			Priority:          flaw.Priority,
			ArbitraryJsonData: flaw.GetArbitraryJsonData(),
			LastDetected:      flaw.LastDetected,
			CreatedAt:         flaw.CreatedAt,
			ScannerID:         flaw.ScannerID,
		},
		Events: utils.Map(flaw.Events, func(ev models.FlawEvent) FlawEventDTO {
			return FlawEventDTO{
				ID:                ev.ID,
				Type:              ev.Type,
				FlawID:            ev.FlawID,
				UserID:            ev.UserID,
				Justification:     ev.Justification,
				ArbitraryJsonData: ev.GetArbitraryJsonData(),
				CreatedAt:         ev.CreatedAt,
			}
		}),
	}
}
