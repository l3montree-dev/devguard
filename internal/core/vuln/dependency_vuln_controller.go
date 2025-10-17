package vuln

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/events"

	"github.com/l3montree-dev/devguard/internal/core/risk"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type dependencyVulnsByPackage struct {
	PackageName string  `json:"packageName"`
	AvgRisk     float64 `json:"avgRisk"`
	MaxRisk     float64 `json:"maxRisk"`
	MaxCVSS     float64 `json:"maxCvss"`
	//TODO: change the name to DependencyVulnCount
	DependencyVulnCount int     `json:"vulnCount"`
	TotalRisk           float64 `json:"totalRisk"`
	//TODO: change the name to DependencyVulns
	DependencyVulns []DependencyVulnDTO `json:"vulns"`
}

type dependencyVulnHTTPController struct {
	dependencyVulnRepository core.DependencyVulnRepository
	dependencyVulnService    core.DependencyVulnService
	projectService           core.ProjectService
	statisticsService        core.StatisticsService
	vulnEventRepository      core.VulnEventRepository
}

type DependencyVulnStatus struct {
	StatusType              string                             `json:"status"`
	Justification           string                             `json:"justification"`
	MechanicalJustification models.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewHTTPController(dependencyVulnRepository core.DependencyVulnRepository, dependencyVulnService core.DependencyVulnService, projectService core.ProjectService, statisticsService core.StatisticsService, vulnEventRepository core.VulnEventRepository) *dependencyVulnHTTPController {
	return &dependencyVulnHTTPController{
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		projectService:           projectService,
		statisticsService:        statisticsService,
		vulnEventRepository:      vulnEventRepository,
	}
}

func (controller dependencyVulnHTTPController) ListByOrgPaged(ctx core.Context) error {

	userAllowedProjectIds, err := controller.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := controller.dependencyVulnRepository.GetDefaultDependencyVulnsByOrgIDPaged(
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
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return convertToDetailedDTO(dependencyVuln)
	}))
}

func (controller dependencyVulnHTTPController) ListByProjectPaged(ctx core.Context) error {
	project := core.GetProject(ctx)

	pagedResp, err := controller.dependencyVulnRepository.GetDefaultDependencyVulnsByProjectIDPaged(
		nil,
		project.ID,

		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return convertToDetailedDTO(dependencyVuln)
	}))
}

func (controller dependencyVulnHTTPController) ListByAssetIDWithoutHandledExternalEventsPaged(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)

	pagedResp, err := controller.dependencyVulnRepository.ListByAssetIDWithoutHandledExternalEvents(
		asset.ID,
		assetVersion.Name,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return convertToDetailedDTO(dependencyVuln)
	}))
}

func (controller dependencyVulnHTTPController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)
	// check if we should list flat - this means not grouped by package
	if ctx.QueryParam("flat") == "true" {
		dependencyVulns, err := controller.dependencyVulnRepository.GetDependencyVulnsByAssetVersionPagedAndFlat(nil, assetVersion.Name, assetVersion.AssetID, core.GetPageInfo(ctx), ctx.QueryParam("search"), core.GetFilterQuery(ctx), core.GetSortQuery(ctx))
		if err != nil {
			return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
		}

		return ctx.JSON(200, dependencyVulns.Map(func(dependencyVuln models.DependencyVuln) any {
			return convertToDetailedDTO(dependencyVuln)
		}))
	}

	pagedResp, packageNameIndexMap, err := controller.dependencyVulnRepository.GetByAssetVersionPaged(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	res := map[string]dependencyVulnsByPackage{}
	for _, dependencyVuln := range pagedResp.Data {
		// get the package name
		if _, ok := res[*dependencyVuln.ComponentPurl]; !ok {
			res[*dependencyVuln.ComponentPurl] = dependencyVulnsByPackage{
				PackageName: *dependencyVuln.ComponentPurl,
			}
		}
		dependencyVulnsByPackage := res[*dependencyVuln.ComponentPurl]
		// append the dependencyVuln to the package
		dependencyVulnsByPackage.DependencyVulns = append(res[*dependencyVuln.ComponentPurl].DependencyVulns, DependencyVulnDTO{
			ID:                    dependencyVuln.ID,
			Artifacts:             dependencyVuln.Artifacts,
			Message:               dependencyVuln.Message,
			AssetVersionName:      dependencyVuln.AssetVersionName,
			AssetID:               dependencyVuln.AssetID.String(),
			State:                 dependencyVuln.State,
			CVE:                   dependencyVuln.CVE,
			CVEID:                 dependencyVuln.CVEID,
			ComponentPurl:         dependencyVuln.ComponentPurl,
			ComponentDepth:        dependencyVuln.ComponentDepth,
			ComponentFixedVersion: dependencyVuln.ComponentFixedVersion,
			Effort:                dependencyVuln.Effort,
			RiskAssessment:        dependencyVuln.RiskAssessment,
			RawRiskAssessment:     dependencyVuln.RawRiskAssessment,
			Priority:              dependencyVuln.Priority,
			LastDetected:          dependencyVuln.LastDetected,
			CreatedAt:             dependencyVuln.CreatedAt,
		})
		res[*dependencyVuln.ComponentPurl] = dependencyVulnsByPackage
	}

	values := make([]dependencyVulnsByPackage, 0, len(res))
	for _, v := range res {
		// calculate the max and average risk
		maxRisk := 0.
		totalRisk := 0.
		maxCvss := 0.

		for _, f := range v.DependencyVulns {
			totalRisk += utils.OrDefault(f.RawRiskAssessment, 0)
			if utils.OrDefault(f.RawRiskAssessment, 0) > maxRisk {
				maxRisk = *f.RawRiskAssessment
			}

			if float64(f.CVE.CVSS) > maxCvss {
				maxCvss = float64(f.CVE.CVSS)
			}
		}
		v.AvgRisk = totalRisk / float64(len(v.DependencyVulns))
		v.MaxRisk = maxRisk
		v.MaxCVSS = maxCvss

		v.TotalRisk = totalRisk
		v.DependencyVulnCount = len(v.DependencyVulns)
		values = append(values, v)
	}

	// sort the value based on the index map
	slices.SortFunc(values, func(a, b dependencyVulnsByPackage) int {
		return packageNameIndexMap[a.PackageName] - packageNameIndexMap[b.PackageName]
	})

	return ctx.JSON(200, core.NewPaged(core.GetPageInfo(ctx), pagedResp.Total, values))
}

func (controller dependencyVulnHTTPController) Mitigate(ctx core.Context) error {
	type justification struct {
		Comment string `json:"comment"`
	}

	var j justification

	err := ctx.Bind(&j)
	if err != nil {
		slog.Error("could not bind justification", "err", err)
	}

	dependencyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	if err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Ctx:           ctx,
		Justification: j.Comment,
	}); err != nil {
		return echo.NewHTTPError(500, "could not mitigate dependencyVuln").WithInternal(err)
	}

	// fetch the dependencyVuln again from the database. We do not know anything what might have changed. The third party integrations might have changed the state of the dependency_vuln.
	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}

	return ctx.JSON(200, convertToDetailedDTO(dependencyVuln))
}

func (controller dependencyVulnHTTPController) Read(ctx core.Context) error {

	dependencyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}
	asset := core.GetAsset(ctx)

	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}

	risk, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))
	dependencyVuln.CVE.Risk = risk
	dependencyVuln.CVE.Vector = vector

	return ctx.JSON(200, convertToDetailedDTO(dependencyVuln))
}

func (controller dependencyVulnHTTPController) Hints(ctx core.Context) error {
	//if enabled in org settings we also want to send hints
	org := core.GetOrg(ctx)

	dependencyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}

	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}

	hints, err := controller.dependencyVulnRepository.GetHintsInOrganizationForVuln(nil, org.ID, *dependencyVuln.ComponentPurl, *dependencyVuln.CVEID)
	if err != nil {
		return err
	}
	return ctx.JSON(200, hints)
}

func (controller dependencyVulnHTTPController) SyncDependencyVulns(ctx core.Context) error {
	/* 	asset := core.GetAsset(ctx)
	   	assetVersion := core.GetAssetVersion(ctx)
	   	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	   	userID := core.GetSession(ctx).GetUserID() */

	type vulnReq struct {
		VulnID string              `json:"vulnID"`
		Event  events.VulnEventDTO `json:"event"`
	}

	type requestBody struct {
		VulnsReq []vulnReq `json:"vulnsReq"`
	}

	var requestData requestBody

	err := json.NewDecoder(ctx.Request().Body).Decode(&requestData)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	for _, r := range requestData.VulnsReq {
		dependencyVuln, err := controller.dependencyVulnRepository.Read(r.VulnID)
		if err != nil {
			slog.Error("could not find dependencyVuln", "err", err, "externalID", r.VulnID)
			continue
		}
		events := dependencyVuln.Events
		for i := range events {
			if events[i].Upstream != 2 {
				continue
			}
			fmt.Println("event id", events[i].ID)
			events[i].Upstream = 1
		}

		dependencyVuln.Events = events
		events[len(events)-1].Apply(&dependencyVuln)

		//update the dependencyVuln and its events
		err = controller.dependencyVulnRepository.Save(nil, &dependencyVuln)
		if err != nil {
			return err
		}

		for _, event := range events {
			if err := controller.vulnEventRepository.Save(nil, &event); err != nil {
				return err
			}
		}

	}

	return ctx.JSON(200, map[string]any{"message": "sync completed"})
}

func (controller dependencyVulnHTTPController) CreateEvent(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	dependencyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}

	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}
	userID := core.GetSession(ctx).GetUserID()

	var status DependencyVulnStatus
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

	ev, err := controller.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &dependencyVuln, statusType, justification, mechanicalJustification, assetVersion.Name, 0)
	if err != nil {
		return err
	}

	//update risk history if the risk has changed
	eventType := models.VulnEventType(statusType)

	for _, artifact := range dependencyVuln.Artifacts {
		if eventType == models.EventTypeAccepted || eventType == models.EventTypeFalsePositive || eventType == models.EventTypeReopened {
			if err := controller.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, time.Now().Add(-30*time.Minute), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)

			}
		}
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

	/* 	if err != nil {
		return echo.NewHTTPError(500, "could not create dependencyVuln event").WithInternal(err)
	} */

	return ctx.JSON(200, convertToDetailedDTO(dependencyVuln))
}

func convertToDetailedDTO(dependencyVuln models.DependencyVuln) detailedDependencyVulnDTO {
	return detailedDependencyVulnDTO{
		DependencyVulnDTO: DependencyVulnDTO{
			ID:                    dependencyVuln.ID,
			Message:               dependencyVuln.Message,
			AssetVersionName:      dependencyVuln.AssetVersionName,
			AssetID:               dependencyVuln.AssetID.String(),
			State:                 dependencyVuln.State,
			CVE:                   dependencyVuln.CVE,
			CVEID:                 dependencyVuln.CVEID,
			ComponentPurl:         dependencyVuln.ComponentPurl,
			ComponentDepth:        dependencyVuln.ComponentDepth,
			ComponentFixedVersion: dependencyVuln.ComponentFixedVersion,
			Effort:                dependencyVuln.Effort,
			RiskAssessment:        dependencyVuln.RiskAssessment,
			RawRiskAssessment:     dependencyVuln.RawRiskAssessment,
			Priority:              dependencyVuln.Priority,
			LastDetected:          dependencyVuln.LastDetected,
			CreatedAt:             dependencyVuln.CreatedAt,
			Artifacts:             dependencyVuln.Artifacts,
			TicketID:              dependencyVuln.TicketID,
			TicketURL:             dependencyVuln.TicketURL,
			ManualTicketCreation:  dependencyVuln.ManualTicketCreation,
			RiskRecalculatedAt:    dependencyVuln.RiskRecalculatedAt,
		},
		Events: utils.Map(dependencyVuln.Events, func(ev models.VulnEvent) events.VulnEventDTO {
			return events.VulnEventDTO{
				ID:                      ev.ID,
				Type:                    ev.Type,
				VulnID:                  ev.VulnID,
				UserID:                  ev.UserID,
				Justification:           ev.Justification,
				MechanicalJustification: ev.MechanicalJustification,
				AssetVersionName:        getAssetVersionName(dependencyVuln.Vulnerability, ev),
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
				Upstream:                ev.Upstream,
			}
		}),
	}
}

func getAssetVersionName(vuln models.Vulnerability, ev models.VulnEvent) string {
	if ev.OriginalAssetVersionName != nil {
		return *ev.OriginalAssetVersionName
	}
	return vuln.AssetVersionName // fallback to the vuln's asset version name if event does not have it
}
