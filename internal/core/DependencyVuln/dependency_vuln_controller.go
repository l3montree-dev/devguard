package DependencyVuln

import (
	"encoding/json"
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

type vulnsByPackage struct {
	PackageName string    `json:"packageName"`
	AvgRisk     float64   `json:"avgRisk"`
	MaxRisk     float64   `json:"maxRisk"`
	VulnCount   int       `json:"vulnCount"`
	TotalRisk   float64   `json:"totalRisk"`
	Vulns       []VulnDTO `json:"vulns"`
}

type repository interface {
	repositories.Repository[string, models.DependencyVulnerability, core.DB]

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]models.DependencyVulnerability, error)
	GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.DependencyVulnerability], map[string]int, error)

	GetVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error)
	GetVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error)
	GetVulnsByAssetIdPagedAndFlat(tx core.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error)
}

type projectService interface {
	ListAllowedProjects(c core.Context) ([]models.Project, error)
}

type vulnService interface {
	UpdateVulnState(tx core.DB, userID string, vuln *models.DependencyVulnerability, statusType string, justification string) (models.VulnEvent, error)
}

type vulnHttpController struct {
	vulnRepository repository
	vulnService    vulnService
	projectService projectService
}

type VulnStatus struct {
	StatusType    string `json:"status"`
	Justification string `json:"justification"`
}

func NewHttpController(vulnRepository repository, vulnService vulnService, projectService projectService) *vulnHttpController {
	return &vulnHttpController{
		vulnRepository: vulnRepository,
		vulnService:    vulnService,
		projectService: projectService,
	}
}

func (c vulnHttpController) ListByOrgPaged(ctx core.Context) error {

	userAllowedProjectIds, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := c.vulnRepository.GetVulnsByOrgIdPaged(
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
		return echo.NewHTTPError(500, "could not get vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(vuln models.DependencyVulnerability) any {
		return convertToDetailedDTO(vuln)
	}))
}

func (c vulnHttpController) ListByProjectPaged(ctx core.Context) error {
	project := core.GetProject(ctx)

	pagedResp, err := c.vulnRepository.GetVulnsByProjectIdPaged(
		nil,
		project.ID,

		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(vuln models.DependencyVulnerability) any {
		return convertToDetailedDTO(vuln)
	}))
}

func (c vulnHttpController) ListPaged(ctx core.Context) error {
	// get the asset
	asset := core.GetAsset(ctx)

	// check if we should list flat - this means not grouped by package
	if ctx.QueryParam("flat") == "true" {
		vulns, err := c.vulnRepository.GetVulnsByAssetIdPagedAndFlat(nil, asset.GetID(), core.GetPageInfo(ctx), ctx.QueryParam("search"), core.GetFilterQuery(ctx), core.GetSortQuery(ctx))
		if err != nil {
			return echo.NewHTTPError(500, "could not get vulns").WithInternal(err)
		}

		return ctx.JSON(200, vulns.Map(func(vuln models.DependencyVulnerability) any {
			return convertToDetailedDTO(vuln)
		}))
	}

	pagedResp, packageNameIndexMap, err := c.vulnRepository.GetByAssetIdPaged(
		nil,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
		asset.GetID(),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get vulns").WithInternal(err)
	}

	res := map[string]vulnsByPackage{}
	for _, vuln := range pagedResp.Data {
		// get the package name
		if _, ok := res[*vuln.ComponentPurl]; !ok {
			res[*vuln.ComponentPurl] = vulnsByPackage{
				PackageName: *vuln.ComponentPurl,
			}
		}
		vulnsByPackage := res[*vuln.ComponentPurl]
		// append the vuln to the package
		vulnsByPackage.Vulns = append(res[*vuln.ComponentPurl].Vulns, VulnDTO{
			ID:                    vuln.ID,
			ScannerID:             vuln.ScannerID,
			Message:               vuln.Message,
			AssetID:               vuln.AssetID.String(),
			State:                 vuln.State,
			CVE:                   vuln.CVE,
			CVEID:                 vuln.CVEID,
			ComponentPurl:         vuln.ComponentPurl,
			ComponentDepth:        vuln.ComponentDepth,
			ComponentFixedVersion: vuln.ComponentFixedVersion,
			Effort:                vuln.Effort,
			RiskAssessment:        vuln.RiskAssessment,
			RawRiskAssessment:     vuln.RawRiskAssessment,
			Priority:              vuln.Priority,
			LastDetected:          vuln.LastDetected,
			CreatedAt:             vuln.CreatedAt,
		})
		res[*vuln.ComponentPurl] = vulnsByPackage
	}

	values := make([]vulnsByPackage, 0, len(res))
	for _, v := range res {
		// calculate the max and average risk
		maxRisk := 0.
		totalRisk := 0.

		for _, f := range v.Vulns {
			totalRisk += utils.OrDefault(f.RawRiskAssessment, 0)
			if utils.OrDefault(f.RawRiskAssessment, 0) > maxRisk {
				maxRisk = *f.RawRiskAssessment
			}
		}
		v.AvgRisk = totalRisk / float64(len(v.Vulns))
		v.MaxRisk = maxRisk
		v.TotalRisk = totalRisk
		v.VulnCount = len(v.Vulns)
		values = append(values, v)
	}

	// sort the value based on the index map
	slices.SortFunc(values, func(a, b vulnsByPackage) int {
		return packageNameIndexMap[a.PackageName] - packageNameIndexMap[b.PackageName]
	})

	return ctx.JSON(200, core.NewPaged(core.GetPageInfo(ctx), pagedResp.Total, values))
}

func (c vulnHttpController) Mitigate(ctx core.Context) error {
	vulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid vuln id")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	if err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Ctx: ctx,
	}); err != nil {
		return echo.NewHTTPError(500, "could not mitigate vuln").WithInternal(err)
	}

	// fetch the vuln again from the database. We do not know anything what might have changed. The third party integrations might have changed the state of the vuln.
	vuln, err := c.vulnRepository.Read(vulnId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find vuln")
	}

	return ctx.JSON(200, convertToDetailedDTO(vuln))
}

func (c vulnHttpController) Read(ctx core.Context) error {
	vulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid vuln id")
	}
	asset := core.GetAsset(ctx)

	vuln, err := c.vulnRepository.Read(vulnId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find vuln")
	}

	risk, vector := risk.RiskCalculation(*vuln.CVE, core.GetEnvironmentalFromAsset(asset))
	vuln.CVE.Risk = risk
	vuln.CVE.Vector = vector

	return ctx.JSON(200, convertToDetailedDTO(vuln))
}

func (c vulnHttpController) CreateEvent(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	vulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid vuln id")
	}

	vuln, err := c.vulnRepository.Read(vulnId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find vuln")
	}
	userID := core.GetSession(ctx).GetUserID()

	var status VulnStatus
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

	err = c.vulnRepository.Transaction(func(tx core.DB) error {
		ev, err := c.vulnService.UpdateVulnState(tx, userID, &vuln, statusType, justification)
		if err != nil {
			return err
		}
		err = thirdPartyIntegration.HandleEvent(core.VulnEvent{
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
		return echo.NewHTTPError(500, "could not create vuln event").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(vuln))
}

func convertToDetailedDTO(vuln models.DependencyVulnerability) detailedVulnDTO {
	return detailedVulnDTO{
		VulnDTO: VulnDTO{
			ID:                    vuln.ID,
			Message:               vuln.Message,
			AssetID:               vuln.AssetID.String(),
			State:                 vuln.State,
			CVE:                   vuln.CVE,
			CVEID:                 vuln.CVEID,
			ComponentPurl:         vuln.ComponentPurl,
			ComponentDepth:        vuln.ComponentDepth,
			ComponentFixedVersion: vuln.ComponentFixedVersion,
			Effort:                vuln.Effort,
			RiskAssessment:        vuln.RiskAssessment,
			RawRiskAssessment:     vuln.RawRiskAssessment,
			Priority:              vuln.Priority,
			LastDetected:          vuln.LastDetected,
			CreatedAt:             vuln.CreatedAt,
			ScannerID:             vuln.ScannerID,
			TicketID:              vuln.TicketID,
			TicketURL:             vuln.TicketURL,
			RiskRecalculatedAt:    vuln.RiskRecalculatedAt,
		},
		Events: utils.Map(vuln.Events, func(ev models.VulnEvent) VulnEventDTO {
			return VulnEventDTO{
				ID:                ev.ID,
				Type:              ev.Type,
				VulnID:            ev.VulnID,
				UserID:            ev.UserID,
				Justification:     ev.Justification,
				ArbitraryJsonData: ev.GetArbitraryJsonData(),
				CreatedAt:         ev.CreatedAt,
			}
		}),
	}
}
