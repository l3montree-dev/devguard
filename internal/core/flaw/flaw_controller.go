package flaw

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/risk"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type flawsByPackage struct {
	PackageName string    `json:"packageName"`
	AvgRisk     float64   `json:"avgRisk"`
	MaxRisk     float64   `json:"maxRisk"`
	FlawCount   int       `json:"flawCount"`
	TotalRisk   float64   `json:"totalRisk"`
	Flaws       []FlawDTO `json:"flaws"`
}

type repository interface {
	repositories.Repository[string, models.Flaw, core.DB]

	GetFlawsByAssetVersion(tx core.DB, assetVersionName string, assetVersionID uuid.UUID) ([]models.Flaw, error)
	GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], map[string]int, error)
	GetDefaultFlawsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error)
	GetDefaultFlawsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error)
	GetFlawsByAssetVersionPagedAndFlat(tx core.DB, assetVersionName string, assetVersionID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error)

	ReadFlawWithAssetEvents(id string) (models.Flaw, []models.FlawEvent, error)
}

type projectService interface {
	ListAllowedProjects(c core.Context) ([]models.Project, error)
}

type flawService interface {
	UpdateFlawState(tx core.DB, assetID uuid.UUID, userID string, flaw *models.Flaw, statusType string, justification string, assetVersionName string) (models.FlawEvent, error)
}

type flawHttpController struct {
	flawRepository repository
	flawService    flawService
	projectService projectService
}

type FlawStatus struct {
	StatusType    string `json:"status"`
	Justification string `json:"justification"`
}

func NewHttpController(flawRepository repository, flawService flawService, projectService projectService) *flawHttpController {
	return &flawHttpController{
		flawRepository: flawRepository,
		flawService:    flawService,
		projectService: projectService,
	}
}

func (c flawHttpController) ListByOrgPaged(ctx core.Context) error {

	userAllowedProjectIds, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := c.flawRepository.GetDefaultFlawsByOrgIdPaged(
		nil,

		utils.Map(userAllowedProjectIds, func(p models.Project) string {
			return p.GetID().String()
		}),
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(flaw models.Flaw) any {
		return convertToDetailedDTO(flaw)
	}))
}

func (c flawHttpController) ListByProjectPaged(ctx core.Context) error {
	project := core.GetProject(ctx)

	fmt.Println("Start.........")

	pagedResp, err := c.flawRepository.GetDefaultFlawsByProjectIdPaged(
		nil,
		project.ID,

		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	fmt.Println("End.........")

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	fmt.Println("End2222222222")

	return ctx.JSON(200, pagedResp.Map(func(flaw models.Flaw) any {
		return convertToDetailedDTO(flaw)
	}))
}

func (c flawHttpController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	// check if we should list flat - this means not grouped by package
	if ctx.QueryParam("flat") == "true" {
		flaws, err := c.flawRepository.GetFlawsByAssetVersionPagedAndFlat(nil, assetVersion.Name, assetVersion.AssetID, core.GetPageInfo(ctx), ctx.QueryParam("search"), core.GetFilterQuery(ctx), core.GetSortQuery(ctx))
		if err != nil {
			return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
		}

		return ctx.JSON(200, flaws.Map(func(flaw models.Flaw) any {
			return convertToDetailedDTO(flaw)
		}))
	}

	pagedResp, packageNameIndexMap, err := c.flawRepository.GetByAssetVersionPaged(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	res := map[string]flawsByPackage{}
	for _, flaw := range pagedResp.Data {
		// get the package name
		if _, ok := res[*flaw.ComponentPurl]; !ok {
			res[*flaw.ComponentPurl] = flawsByPackage{
				PackageName: *flaw.ComponentPurl,
			}
		}
		flawsByPackage := res[*flaw.ComponentPurl]
		// append the flaw to the package
		flawsByPackage.Flaws = append(res[*flaw.ComponentPurl].Flaws, FlawDTO{
			ID:                    flaw.ID,
			ScannerID:             flaw.ScannerID,
			Message:               flaw.Message,
			AssetVersionName:      flaw.AssetVersionName,
			AssetID:               flaw.AssetID.String(),
			State:                 flaw.State,
			CVE:                   flaw.CVE,
			CVEID:                 flaw.CVEID,
			ComponentPurl:         flaw.ComponentPurl,
			ComponentDepth:        flaw.ComponentDepth,
			ComponentFixedVersion: flaw.ComponentFixedVersion,
			Effort:                flaw.Effort,
			RiskAssessment:        flaw.RiskAssessment,
			RawRiskAssessment:     flaw.RawRiskAssessment,
			Priority:              flaw.Priority,
			LastDetected:          flaw.LastDetected,
			CreatedAt:             flaw.CreatedAt,
		})
		res[*flaw.ComponentPurl] = flawsByPackage
	}

	values := make([]flawsByPackage, 0, len(res))
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
	slices.SortFunc(values, func(a, b flawsByPackage) int {
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

	flaw, flawEvents, err := c.flawRepository.ReadFlawWithAssetEvents(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	flaw.Events = utils.Filter(flawEvents, func(ev models.FlawEvent) bool {
		return ev.FlawID == flaw.ID || ev.Type != models.EventTypeDetected
	})

	risk, vector := risk.RiskCalculation(*flaw.CVE, core.GetEnvironmentalFromAsset(asset))
	flaw.CVE.Risk = risk
	flaw.CVE.Vector = vector

	return ctx.JSON(200, convertToDetailedDTO(flaw))
}

func (c flawHttpController) CreateEvent(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
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
		ev, err := c.flawService.UpdateFlawState(tx, asset.ID, userID, &flaw, statusType, justification, assetVersion.Name)
		if err != nil {
			return err
		}
		err = thirdPartyIntegration.HandleEvent(core.FlawEvent{
			Ctx:   ctx,
			Event: ev,
		})
		// we do not want the transaction to be rolled back if the third party integration fails
		if err != nil {
			// just log the error
			slog.Error("could not handle event", "err", err)
		}
		return nil
	})
	if err != nil {
		return echo.NewHTTPError(500, "could not create flaw event").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(flaw))
}

func convertToDetailedDTO(flaw models.Flaw) detailedFlawDTO {
	return detailedFlawDTO{
		FlawDTO: FlawDTO{
			ID:                    flaw.ID,
			Message:               flaw.Message,
			AssetVersionName:      flaw.AssetVersionName,
			AssetID:               flaw.AssetID.String(),
			State:                 flaw.State,
			CVE:                   flaw.CVE,
			CVEID:                 flaw.CVEID,
			ComponentPurl:         flaw.ComponentPurl,
			ComponentDepth:        flaw.ComponentDepth,
			ComponentFixedVersion: flaw.ComponentFixedVersion,
			Effort:                flaw.Effort,
			RiskAssessment:        flaw.RiskAssessment,
			RawRiskAssessment:     flaw.RawRiskAssessment,
			Priority:              flaw.Priority,
			LastDetected:          flaw.LastDetected,
			CreatedAt:             flaw.CreatedAt,
			ScannerID:             flaw.ScannerID,
			TicketID:              flaw.TicketID,
			TicketURL:             flaw.TicketURL,
			RiskRecalculatedAt:    flaw.RiskRecalculatedAt,
		},
		Events: utils.Map(flaw.Events, func(ev models.FlawEvent) FlawEventDTO {
			return FlawEventDTO{
				ID:                ev.ID,
				Type:              ev.Type,
				FlawID:            ev.FlawID,
				UserID:            ev.UserID,
				Justification:     ev.Justification,
				AssetVersion:      flaw.AssetVersionName,
				ArbitraryJsonData: ev.GetArbitraryJsonData(),
				CreatedAt:         ev.CreatedAt,
			}
		}),
	}
}
