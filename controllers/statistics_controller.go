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

// @Summary Get average fixing times for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Success 200 {object} dtos.RemediationTimeAverages
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/average-fixing-time/ [get]
func (c *StatisticsController) GetAverageFixingTimes(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := ctx.QueryParam("artifactName")

	averages, err := c.statisticsRepository.AverageFixingTimes(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average fixing time").WithInternal(err)
	}
	return ctx.JSON(200, averages)
}


// @Summary Get risk history for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Param start query string true "Start date (YYYY-MM-DD)"
// @Param end query string true "End date (YYYY-MM-DD)"
// @Success 200 {array} dtos.RiskHistoryDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/risk-history/ [get]
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

// @Summary Get CVEs with known exploits for an asset
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} models.CVE
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/number-of-exploits/ [get]
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

// @Summary Get risk history for a release
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Param start query string true "Start date (YYYY-MM-DD)"
// @Param end query string true "End date (YYYY-MM-DD)"
// @Success 200 {array} dtos.RiskHistoryDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/stats/risk-history/ [get]
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

// @Summary Get component risk distribution for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/component-risk/ [get]
func (c *StatisticsController) GetComponentRisk(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := ctx.QueryParam("artifactName")
	results, err := c.statisticsService.GetComponentRisk(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

// @Summary Get average remediation times for a release
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} dtos.RemediationTimeAverages
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/stats/average-fixing-time/ [get]
func (c *StatisticsController) GetAverageReleaseFixingTime(ctx shared.Context) error {
	releaseIDParam := shared.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	averages, err := c.statisticsService.GetRemediationTimeAveragesForRelease(ctx.Request().Context(), releaseID)
	if err != nil {
		slog.Error("could not get remediation time averages for release", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, averages)
}

// @Summary Get organization statistics overview
// @Description Returns aggregated security statistics for an organization, including vulnerability distribution, top vulnerable projects/assets/artifacts, most used components, common CVEs, risk history, remediation metrics, and ecosystem usage. All queries are executed in parallel.
// @Tags Organizations
// @Produce json
// @Param organization path string true "Organization slug"
// @Param orgComponentsLimit query int false "Max number of top vulnerable projects/assets/artifacts to return (default: 5)"
// @Param topCVEsLimit query int false "Max number of top CVEs to return (default: 5)"
// @Param topComponentsLimit query int false "Max number of top components to return (default: 5)"
// @Param topEcosystemsLimit query int false "Max number of top ecosystems to return (default: 5)"
// @Success 200 {object} dtos.OrgOverview
// @Router /organizations/{organization}/stats/vuln-statistics/ [get]
func (c *StatisticsController) GetOrgStatistics(ctx shared.Context) error {
	org := shared.GetOrg(ctx)

	orgComponentsLimit, topCVEsLimit, topComponentsLimit, topEcosystemsLimit := evaluateOrgStatisticsParams(ctx)

	now := time.Now()
	reqCtx := ctx.Request().Context()

	res := utils.Concurrently(
		func() (any, error) { // 0: distribution
			return c.statisticsRepository.VulnClassificationByOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 1: structure
			return c.statisticsRepository.GetOrgStructureDistribution(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 2: projects
			return c.statisticsRepository.GetMostVulnerableProjectsInOrg(reqCtx, nil, org.ID, orgComponentsLimit)
		},
		func() (any, error) { // 3: assets
			return c.statisticsRepository.GetMostVulnerableAssetsInOrg(reqCtx, nil, org.ID, orgComponentsLimit)
		},
		func() (any, error) { // 4: artifacts
			return c.statisticsRepository.GetMostVulnerableArtifactsInOrg(reqCtx, nil, org.ID, orgComponentsLimit)
		},
		func() (any, error) { // 5: topComponents
			return c.statisticsRepository.GetMostUsedComponentsInOrg(reqCtx, nil, org.ID, topComponentsLimit)
		},
		func() (any, error) { // 6: topCVEs
			return c.statisticsRepository.GetMostCommonCVEsInOrg(reqCtx, nil, org.ID, topCVEsLimit)
		},
		func() (any, error) { // 7: vulnEventAverages
			return c.statisticsRepository.GetWeeklyAveragePerVulnEventType(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 8: riskHistory
			return c.artifactRiskHistoryRepository.GetRiskHistoryForOrg(reqCtx, nil, org.ID, now.Add(-30*time.Hour*24), now)
		},
		func() (any, error) { // 9: openCodeRiskAverage
			return c.statisticsRepository.GetAverageAmountOfOpenCodeRisksForProjectsInOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 10: openVulnAverage
			return c.statisticsRepository.GetAverageAmountOfOpenVulnsPerProjectBySeverityInOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 11: topEcosystems
			return c.statisticsService.GetTopEcosystemsInOrg(reqCtx, org.ID, topEcosystemsLimit)
		},
		func() (any, error) { // 12: maliciousPackages
			return c.statisticsRepository.FindMaliciousPackagesInOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 13: averageAge
			return c.statisticsRepository.GetAverageAgeOfDependenciesAcrossOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 14: averageRemediations
			return c.statisticsRepository.GetAverageRemediationTimesAcrossOrg(reqCtx, nil, org.ID)
		},
		func() (any, error) { // 15: remediationTypeDistributionRows
			return c.statisticsRepository.GetRemediationTypeDistributionAcrossOrg(reqCtx, nil, org.ID)
		},
	)

	if res.HasErrors() {
		slog.Error("could not get org statistics", "errors", res.Errors())
		return echo.NewHTTPError(500, "could not get org statistics")
	}

	vulnEventAverageDistribution := dtos.AverageVulnEventsPerWeek{}
	for _, average := range res.GetValue(7).([]dtos.VulnEventAverage) {
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

	remediationTypeDistribution := dtos.RemediationTypeDistribution{}
	for _, row := range res.GetValue(15).([]dtos.RemediationTypeDistributionRow) {
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
		VulnDistribution:               res.GetValue(0).(dtos.Distribution),
		OrgStructure:                   res.GetValue(1).(dtos.OrgStructureDistribution),
		TopProjects:                    res.GetValue(2).([]dtos.VulnDistributionInStructure),
		TopAssets:                      res.GetValue(3).([]dtos.VulnDistributionInStructure),
		TopArtifacts:                   res.GetValue(4).([]dtos.VulnDistributionInStructure),
		TopComponents:                  res.GetValue(5).([]dtos.ComponentUsageAcrossOrg),
		TopCVEs:                        res.GetValue(6).([]dtos.CVEOccurrencesAcrossOrg),
		OrgRiskHistory:                 res.GetValue(8).([]dtos.OrgRiskHistory),
		AverageOpenCodeRisksPerProject: res.GetValue(9).(float32),
		ProjectOpenVulnAverage:         res.GetValue(10).(dtos.ProjectVulnCountAverageBySeverity),
		TopEcosystems:                  res.GetValue(11).([]dtos.EcosystemUsage),
		MaliciousPackages:              res.GetValue(12).([]dtos.MaliciousPackageInOrg),
		AverageAgeOfDependencies:       res.GetValue(13).(time.Duration),
		AverageRemediationTimes:        res.GetValue(14).(dtos.AverageRemediationTimes),
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
