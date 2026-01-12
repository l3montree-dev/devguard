package controllers

import (
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vulndb"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
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
	DependencyVulns []dtos.DependencyVulnDTO `json:"vulns"`
}

type DependencyVulnController struct {
	dependencyVulnRepository shared.DependencyVulnRepository
	dependencyVulnService    shared.DependencyVulnService
	projectService           shared.ProjectService
	statisticsService        shared.StatisticsService
	vulnEventRepository      shared.VulnEventRepository
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
}

type DependencyVulnStatus struct {
	StatusType              string                           `json:"status"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewDependencyVulnController(dependencyVulnRepository shared.DependencyVulnRepository, dependencyVulnService shared.DependencyVulnService, projectService shared.ProjectService, statisticsService shared.StatisticsService, vulnEventRepository shared.VulnEventRepository, synchronizer utils.FireAndForgetSynchronizer) *DependencyVulnController {
	return &DependencyVulnController{
		dependencyVulnRepository:  dependencyVulnRepository,
		dependencyVulnService:     dependencyVulnService,
		projectService:            projectService,
		statisticsService:         statisticsService,
		vulnEventRepository:       vulnEventRepository,
		FireAndForgetSynchronizer: synchronizer,
	}
}

func (controller DependencyVulnController) ListByOrgPaged(ctx shared.Context) error {

	userAllowedProjectIds, err := controller.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := controller.dependencyVulnRepository.GetDefaultDependencyVulnsByOrgIDPaged(
		nil,

		utils.Map(userAllowedProjectIds, func(p models.Project) string {
			return p.GetID().String()
		}),
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return transformer.DependencyVulnToDetailedDTO(dependencyVuln)
	}))
}

func (controller DependencyVulnController) ListByProjectPaged(ctx shared.Context) error {
	project := shared.GetProject(ctx)

	pagedResp, err := controller.dependencyVulnRepository.GetDefaultDependencyVulnsByProjectIDPaged(
		nil,
		project.ID,

		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return transformer.DependencyVulnToDetailedDTO(dependencyVuln)
	}))
}

func (controller DependencyVulnController) ListByAssetIDWithoutHandledExternalEventsPaged(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	pagedResp, err := controller.dependencyVulnRepository.ListByAssetIDWithoutHandledExternalEvents(
		asset.ID,
		assetVersion.Name,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(dependencyVuln models.DependencyVuln) any {
		return transformer.DependencyVulnToDetailedDTO(dependencyVuln)
	}))
}

// @Summary List dependency vulnerabilities
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param flat query string false "Flat list flag"
// @Param search query string false "Search term"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/dependency-vulns [get]
func (controller DependencyVulnController) ListPaged(ctx shared.Context) error {
	// get the asset
	assetVersion := shared.GetAssetVersion(ctx)
	// check if we should list flat - this means not grouped by package
	if ctx.QueryParam("flat") == "true" {
		dependencyVulns, err := controller.dependencyVulnRepository.GetDependencyVulnsByAssetVersionPagedAndFlat(nil, assetVersion.Name, assetVersion.AssetID, shared.GetPageInfo(ctx), ctx.QueryParam("search"), shared.GetFilterQuery(ctx), shared.GetSortQuery(ctx))
		if err != nil {
			return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
		}

		return ctx.JSON(200, dependencyVulns.Map(func(dependencyVuln models.DependencyVuln) any {
			return transformer.DependencyVulnToDetailedDTO(dependencyVuln)
		}))
	}

	pagedResp, packageNameIndexMap, err := controller.dependencyVulnRepository.GetByAssetVersionPaged(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
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
		dependencyVulnsByPackage.DependencyVulns = append(res[*dependencyVuln.ComponentPurl].DependencyVulns, transformer.DependencyVulnToDTO(dependencyVuln))
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

	return ctx.JSON(200, shared.NewPaged(shared.GetPageInfo(ctx), pagedResp.Total, values))
}

func (controller DependencyVulnController) Mitigate(ctx shared.Context) error {
	type justification struct {
		Comment string `json:"comment"`
	}

	var j justification

	err := ctx.Bind(&j)
	if err != nil {
		slog.Error("could not bind justification", "err", err)
	}

	dependencyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}

	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)

	if err = thirdPartyIntegrations.HandleEvent(shared.ManualMitigateEvent{
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

	return ctx.JSON(200, transformer.DependencyVulnToDetailedDTO(dependencyVuln))
}

// @Summary Get dependency vulnerability details
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param dependencyVulnID path string true "Vulnerability ID"
// @Success 200 {object} dtos.DetailedDependencyVulnDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/dependency-vulns/{dependencyVulnID} [get]
func (controller DependencyVulnController) Read(ctx shared.Context) error {

	dependencyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}
	asset := shared.GetAsset(ctx)

	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}

	risk, vector := vulndb.RiskCalculation(*dependencyVuln.CVE, shared.GetEnvironmentalFromAsset(asset))
	dependencyVuln.CVE.Risk = risk
	dependencyVuln.CVE.Vector = vector

	return ctx.JSON(200, transformer.DependencyVulnToDetailedDTO(dependencyVuln))
}

func (controller DependencyVulnController) Hints(ctx shared.Context) error {
	//if enabled in org settings we also want to send hints
	org := shared.GetOrg(ctx)

	dependencyVulnID, _, err := shared.GetVulnID(ctx)
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

func (controller DependencyVulnController) SyncDependencyVulns(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)

	type vulnReq struct {
		VulnID string            `json:"vulnId"`
		Event  dtos.VulnEventDTO `json:"event"`
	}

	type requestBody struct {
		VulnsReq []vulnReq `json:"vulnsReq"`
	}

	var requestData requestBody

	err := json.NewDecoder(ctx.Request().Body).Decode(&requestData)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	vulns := make([]models.DependencyVuln, 0, len(requestData.VulnsReq))

	for _, r := range requestData.VulnsReq {
		dependencyVuln, err := controller.dependencyVulnRepository.Read(r.VulnID)
		if err != nil {
			slog.Error("could not find dependencyVuln", "err", err, "externalID", r.VulnID)
			continue
		}
		vulns = append(vulns, dependencyVuln)
		events := dependencyVuln.Events
		for i := range events {
			if events[i].Upstream != 2 {
				continue
			}
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

	controller.FireAndForget(func() {
		err := controller.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	return ctx.JSON(200, map[string]any{"message": "sync completed"})
}

// @Summary Create vulnerability event
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param dependencyVulnID path string true "Vulnerability ID"
// @Param body body object true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/dependency-vulns/{dependencyVulnID} [post]
func (controller DependencyVulnController) CreateEvent(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	dependencyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid dependencyVuln id")
	}

	dependencyVuln, err := controller.dependencyVulnRepository.Read(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}
	userID := shared.GetSession(ctx).GetUserID()

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

	ev, err := controller.dependencyVulnService.CreateVulnEventAndApply(nil, asset.ID, userID, &dependencyVuln, dtos.VulnEventType(statusType), justification, mechanicalJustification, assetVersion.Name, dtos.UpstreamStateInternal)
	if err != nil {
		return err
	}

	//update risk history if the risk has changed
	eventType := dtos.VulnEventType(statusType)

	for _, artifact := range dependencyVuln.Artifacts {
		if eventType == dtos.EventTypeAccepted || eventType == dtos.EventTypeFalsePositive || eventType == dtos.EventTypeReopened {
			if err := controller.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, time.Now().Add(-30*time.Minute), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
			}
		}
	}

	err = thirdPartyIntegration.HandleEvent(shared.VulnEvent{
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

	return ctx.JSON(200, transformer.DependencyVulnToDetailedDTO(dependencyVuln))
}
