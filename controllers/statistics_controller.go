package controllers

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type StatisticsController struct {
	statisticsService      shared.StatisticsService
	statisticsRepository   shared.StatisticsRepository
	assetVersionRepository shared.AssetVersionRepository
}

func NewStatisticsController(statisticsService shared.StatisticsService, statisticsRepository shared.StatisticsRepository, assetVersionRepository shared.AssetVersionRepository) *StatisticsController {
	return &StatisticsController{
		statisticsService:      statisticsService,
		statisticsRepository:   statisticsRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

func (c *StatisticsController) GetAverageFixingTime(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	severity := ctx.QueryParam("severity")
	if severity == "" {
		slog.Warn("severity query parameter is required")
		return ctx.JSON(400, map[string]string{
			"error": "severity query parameter is required",
		})
	}

	artifact := ctx.QueryParam("artifactName")
	// check the severity value
	if err := checkSeverity(severity); err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	res := utils.Concurrently(
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, severity)
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTimeByCvss(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, severity)
		},
	)

	if res.HasErrors() {
		slog.Error("could not get average fixing time", "errors", res.Errors())
		return ctx.JSON(500, map[string]string{
			"error": "could not get average fixing time",
		})
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds":       res.GetValue(0).(time.Duration).Abs().Seconds(),
		"averageFixingTimeSecondsByCvss": res.GetValue(1).(time.Duration).Abs().Seconds(),
	})
}

func checkSeverity(severity string) error {
	if severity == "" {
		slog.Warn("severity query parameter is required")
		return fmt.Errorf("severity query parameter is required")
	}
	// check the severity value
	if severity != "critical" && severity != "high" && severity != "medium" && severity != "low" {
		slog.Warn("severity query parameter must be one of critical, high, medium, low")
		return fmt.Errorf("severity query parameter must be one of critical, high, medium, low")
	}
	return nil
}

func (c *StatisticsController) GetArtifactRiskHistory(ctx shared.Context) error {
	artifact := ctx.QueryParam("artifactName")
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	assetVersion := shared.GetAssetVersion(ctx)
	asset := shared.GetAsset(ctx)

	results, err := c.getArtifactRiskHistory(utils.EmptyThenNil(artifact), assetVersion.Name, asset.ID, start, end)
	if err != nil {
		slog.Error("Error getting assetversion risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	dtoResults := make([]dtos.RiskHistoryDTO, 0, len(results))
	for _, r := range results {
		dtoResults = append(dtoResults, transformer.ArtifactRiskHistoryToDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

func (c *StatisticsController) getArtifactRiskHistory(artifactName *string, assetVersionName string, assetID uuid.UUID, start, end string) ([]models.ArtifactRiskHistory, error) {

	if start == "" || end == "" {
		return nil, fmt.Errorf("start and end query parameters are required")
	}

	// parse the dates
	beginTime, err := time.Parse(time.DateOnly, start)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing begin date")
	}

	endTime, err := time.Parse(time.DateOnly, end)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing end date")
	}

	return c.statisticsService.GetArtifactRiskHistory(artifactName, assetVersionName, assetID, beginTime, endTime)
}

func (c *StatisticsController) GetCVESWithKnownExploits(ctx shared.Context) error {
	var cves []models.CVE
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	cves, err = c.statisticsRepository.CVESWithKnownExploitsInAssetVersion(assetVersion)
	if err != nil {
		return ctx.NoContent(500)
	}

	return ctx.JSON(200, cves)
}

// GetReleaseRiskHistory returns aggregated artifact risk history for a given release
func (c *StatisticsController) GetReleaseRiskHistory(ctx shared.Context) error {
	// parse release id from param
	releaseIDParam := shared.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")
	if start == "" || end == "" {
		return ctx.JSON(400, map[string]string{"error": "start and end query parameters are required"})
	}
	beginTime, err := time.Parse(time.DateOnly, start)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid start date"})
	}
	endTime, err := time.Parse(time.DateOnly, end)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid end date"})
	}

	// delegate to service
	res, err := c.statisticsService.GetReleaseRiskHistory(releaseID, beginTime, endTime)
	if err != nil {
		slog.Error("could not get release risk history", "err", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	dtoResults := make([]dtos.RiskHistoryDTO, 0, len(res))
	for _, r := range res {
		dtoResults = append(dtoResults, transformer.ArtifactRiskHistoryToDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

func (c *StatisticsController) GetComponentRisk(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := ctx.QueryParam("artifactName")
	results, err := c.statisticsService.GetComponentRisk(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

// GetAverageReleaseFixingTime returns the average fixing time (seconds) for a release across all included artifacts
func (c *StatisticsController) GetAverageReleaseFixingTime(ctx shared.Context) error {
	releaseIDParam := shared.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	severity := ctx.QueryParam("severity")
	if severity == "" {
		return ctx.JSON(400, map[string]string{"error": "severity query parameter is required"})
	}
	if err := checkSeverity(severity); err != nil {
		return ctx.JSON(400, map[string]string{"error": err.Error()})
	}

	res := utils.Concurrently(
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTimeForRelease(releaseID, severity)
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTimeByCvssForRelease(releaseID, severity)
		},
	)

	if res.HasErrors() {
		slog.Error("could not get average fixing time for release", "errors", res.Errors())
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds":       res.GetValue(0).(time.Duration).Abs().Seconds(),
		"averageFixingTimeSecondsByCvss": res.GetValue(1).(time.Duration).Abs().Seconds(),
	})
}

func (c *StatisticsController) GetOrgStatistics(ctx shared.Context) error {
	org := shared.GetOrg(ctx)

	distribution, err := c.statisticsRepository.VulnClassificationByOrg(org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get vuln distribution in org")
	}
	structure, err := c.statisticsRepository.GetOrgStructureDistribution(org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get org structure")
	}

	// get most vulnerable components of org
	projects, err := c.statisticsRepository.GetMostVulnerableProjectsInOrg(org.ID, 5)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable projects in org")
	}
	assets, err := c.statisticsRepository.GetMostVulnerableAssetsInOrg(org.ID, 5)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable assets in org")
	}
	artifacts, err := c.statisticsRepository.GetMostVulnerableArtifactsInOrg(org.ID, 5)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable artifacts in org")
	}

	topComponents, err := c.statisticsRepository.GetMostUsedComponentsInOrg(org.ID, 10)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most used components across org")
	}

	topCVEs, err := c.statisticsRepository.GetMostCommonCVEsInOrg(org.ID, 10)
	if err != nil {
		return err
	}

	orgStatistics := dtos.OrgOverview{
		VulnDistribution: distribution,
		OrgStructure:     structure,
		TopProjects:      projects,
		TopAssets:        assets,
		TopArtifacts:     artifacts,
		TopComponents:    topComponents,
		TopCVES:          topCVEs,
	}

	return ctx.JSON(200, orgStatistics)
}
