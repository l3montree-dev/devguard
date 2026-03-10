package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
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
	statisticsService             shared.StatisticsService
	statisticsRepository          shared.StatisticsRepository
	assetVersionRepository        shared.AssetVersionRepository
	artifactRiskHistoryRepository shared.ArtifactRiskHistoryRepository
}

func NewStatisticsController(statisticsService shared.StatisticsService, statisticsRepository shared.StatisticsRepository, assetVersionRepository shared.AssetVersionRepository, artifactRiskHistoryRepository shared.ArtifactRiskHistoryRepository) *StatisticsController {
	return &StatisticsController{
		statisticsService:             statisticsService,
		statisticsRepository:          statisticsRepository,
		assetVersionRepository:        assetVersionRepository,
		artifactRiskHistoryRepository: artifactRiskHistoryRepository,
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
			return c.statisticsService.GetAverageFixingTime(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, severity)
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTimeByCvss(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, severity)
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

	results, err := c.getArtifactRiskHistory(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, asset.ID, start, end)
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

func (c *StatisticsController) getArtifactRiskHistory(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start, end string) ([]models.ArtifactRiskHistory, error) {

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

	return c.statisticsService.GetArtifactRiskHistory(ctx, artifactName, assetVersionName, assetID, beginTime, endTime)
}

func (c *StatisticsController) GetCVESWithKnownExploits(ctx shared.Context) error {
	var cves []models.CVE
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(ctx.Request().Context(), nil, asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	cves, err = c.statisticsRepository.CVESWithKnownExploitsInAssetVersion(ctx.Request().Context(), nil, assetVersion)
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
	res, err := c.statisticsService.GetReleaseRiskHistory(ctx.Request().Context(), releaseID, beginTime, endTime)
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
	results, err := c.statisticsService.GetComponentRisk(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)

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
			return c.statisticsService.GetAverageFixingTimeForRelease(ctx.Request().Context(), releaseID, severity)
		},
		func() (any, error) {
			return c.statisticsService.GetAverageFixingTimeByCvssForRelease(ctx.Request().Context(), releaseID, severity)
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

	orgComponentsLimit, topCVEsLimit, topComponentsLimit, topEcosystemsLimit := evaluateOrgStatisticsParams(ctx)

	distribution, err := c.statisticsRepository.VulnClassificationByOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get vuln distribution in org").WithInternal(err)
	}
	structure, err := c.statisticsRepository.GetOrgStructureDistribution(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get org structure").WithInternal(err)
	}

	// get most vulnerable components of org
	projects, err := c.statisticsRepository.GetMostVulnerableProjectsInOrg(ctx.Request().Context(), nil, org.ID, orgComponentsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable projects in org").WithInternal(err)
	}
	assets, err := c.statisticsRepository.GetMostVulnerableAssetsInOrg(ctx.Request().Context(), nil, org.ID, orgComponentsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable assets in org").WithInternal(err)
	}
	artifacts, err := c.statisticsRepository.GetMostVulnerableArtifactsInOrg(ctx.Request().Context(), nil, org.ID, orgComponentsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most vulnerable artifacts in org").WithInternal(err)
	}

	topComponents, err := c.statisticsRepository.GetMostUsedComponentsInOrg(ctx.Request().Context(), nil, org.ID, topComponentsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most used components across org").WithInternal(err)
	}

	topCVEs, err := c.statisticsRepository.GetMostCommonCVEsInOrg(ctx.Request().Context(), nil, org.ID, topCVEsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get most common CVEs across org").WithInternal(err)
	}

	vulnEventAverages, err := c.statisticsRepository.GetWeeklyAveragePerVulnEventType(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get weekly average for vuln events").WithInternal(err)
	}

	vulnEventAverageDistribution := dtos.AverageVulnEventsPerWeek{}
	for _, average := range vulnEventAverages {
		switch average.VulnEventType {
		case dtos.EventTypeDetected:
			vulnEventAverageDistribution.AverageDetectedEvents = average.Average
		case dtos.EventTypeAccepted:
			vulnEventAverageDistribution.AverageAcceptedEvents = average.Average
		case dtos.EventTypeFalsePositive:
			vulnEventAverageDistribution.AverageFalsePositiveEvents = average.Average
		case dtos.EventTypeFixed:
			vulnEventAverageDistribution.AverageFixedEvents = average.Average
		case dtos.EventTypeReopened:
			vulnEventAverageDistribution.AverageReopenedEvents = average.Average
		}
	}

	now := time.Now()
	riskHistory, err := c.artifactRiskHistoryRepository.GetRiskHistoryForOrg(ctx.Request().Context(), nil, org.ID, now.Add(-30*time.Hour*24), now)
	if err != nil {
		return echo.NewHTTPError(500, "could not get risk history for org").WithInternal(err)
	}

	openCodeRiskAverage, err := c.statisticsRepository.GetAverageAmountOfOpenCodeRisksForProjectsInOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average amount of open code risks for org").WithInternal(err)
	}

	openVulnAverage, err := c.statisticsRepository.GetAverageAmountOfOpenVulnsPerProjectBySeverityInOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average amount of open vulns for org").WithInternal(err)
	}

	topEcosystems, err := c.statisticsService.GetTopEcosystemsInOrg(org.ID, topEcosystemsLimit)
	if err != nil {
		return echo.NewHTTPError(500, "could not get top ecosystem for org").WithInternal(err)
	}

	maliciousPackages, err := c.statisticsRepository.FindMaliciousPackagesInOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find malicious packages for org").WithInternal(err)
	}

	averageAge, err := c.statisticsRepository.GetAverageAgeOfDependenciesAcrossOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average age of dependencies").WithInternal(err)
	}

	averageRemediations, err := c.statisticsRepository.GetAverageRemediationTimesAcrossOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average remediation times").WithInternal(err)
	}

	remediationTypeDistributionRows, err := c.statisticsRepository.GetRemediationTypeDistributionAcrossOrg(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get percentage distribution for remediation types").WithInternal(err)
	}

	remediationTypeDistribution := dtos.RemediationTypeDistribution{}
	for _, row := range remediationTypeDistributionRows {
		switch row.Type {
		case string(dtos.EventTypeAccepted):
			remediationTypeDistribution.AcceptedPercentage = row.Percentage
		case string(dtos.EventTypeFixed):
			remediationTypeDistribution.FixedPercentage = row.Percentage
		case string(dtos.EventTypeFalsePositive):
			remediationTypeDistribution.FalsePositivePercentage = row.Percentage
		}
	}

	orgStatistics := dtos.OrgOverview{
		VulnEventAverage:               vulnEventAverageDistribution,
		VulnDistribution:               distribution,
		OrgStructure:                   structure,
		TopProjects:                    projects,
		TopAssets:                      assets,
		TopArtifacts:                   artifacts,
		TopComponents:                  topComponents,
		TopCVEs:                        topCVEs,
		OrgRiskHistory:                 riskHistory,
		AverageOpenCodeRisksPerProject: openCodeRiskAverage,
		ProjectOpenVulnAverage:         openVulnAverage,
		TopEcosystems:                  topEcosystems,
		MaliciousPackages:              maliciousPackages,
		AverageAgeOfDependencies:       averageAge,
		AverageRemediationTimes:        averageRemediations,
		RemediationTypeDistribution:    remediationTypeDistribution,
	}

	return ctx.JSON(200, orgStatistics)
}

func evaluateOrgStatisticsParams(ctx shared.Context) (orgComponentsLimit, topCVEsLimit, topComponentsLimit, topEcosystemsLimit int) {
	// currently we use the same default value for all query params, if we want to specify the default for each param we can do that with a map
	defaultValue := 5
	queryParams := []string{"orgComponentsLimit", "topCVEsLimit", "topComponentsLimit", "topEcosystemsLimit"}
	queryValues := []int{}
	for _, paramName := range queryParams {
		if ctx.QueryParam(paramName) != "" {
			limit, err := strconv.Atoi(ctx.QueryParam(paramName))
			if err == nil {
				queryValues = append(queryValues, limit)
			} else {
				slog.Warn("invalid value for query param detected, using default value", "param", paramName)
				queryValues = append(queryValues, defaultValue)
			}
		} else {
			// use default value
			queryValues = append(queryValues, defaultValue)
		}

	}
	return queryValues[0], queryValues[1], queryValues[2], queryValues[3]
}
