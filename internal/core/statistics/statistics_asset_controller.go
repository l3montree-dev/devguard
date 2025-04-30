package statistics

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

type statisticsService interface {
	GetComponentRisk(assetVersionName string, assetID uuid.UUID) (map[string]float64, error)
	GetAssetVersionRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
	GetAssetVersionCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
	GetAssetVersionRiskHistory(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error)
	GetDependencyVulnAggregationStateAndChangeSince(assetVersionName string, assetID uuid.UUID, calculateChangeTo time.Time) (DependencyVulnAggregationStateAndChange, error)

	GetDependencyVulnCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error)
	GetDependencyCountPerscanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error)
	GetAverageFixingTime(assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error)
	UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, start time.Time, end time.Time, updateProject bool) error

	GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error)
}

type httpController struct {
	statisticsService      statisticsService
	assetVersionRepository core.AssetVersionRepository
	assetRepository        core.AssetRepository
	projectService         core.ProjectService
}

func NewHttpController(statisticsService statisticsService, assetRepository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, projectService core.ProjectService) *httpController {
	return &httpController{
		statisticsService:      statisticsService,
		assetVersionRepository: assetVersionRepository,
		projectService:         projectService,
		assetRepository:        assetRepository,
	}
}

func (c *httpController) GetComponentRisk(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	results, err := c.statisticsService.GetComponentRisk(assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetDependencyCountPerScanner(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	results, err := c.statisticsService.GetDependencyCountPerscanner(assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetDependencyVulnCountByScannerId(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	results, err := c.statisticsService.GetDependencyVulnCountByScannerId(assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAssetVersionRiskDistribution(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	results, err := c.statisticsService.GetAssetVersionRiskDistribution(assetVersion.Name, assetVersion.AssetID, asset.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAssetVersionCvssDistribution(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	results, err := c.statisticsService.GetAssetVersionCvssDistribution(assetVersion.Name, assetVersion.AssetID, asset.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAverageAssetVersionFixingTime(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	severity := ctx.QueryParam("severity")
	if severity == "" {
		slog.Warn("severity query parameter is required")
		return ctx.JSON(400, map[string]string{
			"error": "severity query parameter is required",
		})
	}

	// check the severity value
	if err := checkSeverity(severity); err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	duration, err := c.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, severity)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": duration.Abs().Seconds(),
	})
}

func aggregateRiskDistribution(results []models.AssetRiskDistribution, id uuid.UUID, label string) models.AssetRiskDistribution {
	if len(results) == 0 {
		return models.AssetRiskDistribution{}
	}

	lowCount := 0
	mediumCount := 0
	highCount := 0
	criticalCount := 0

	for _, r := range results {
		lowCount += r.Low
		mediumCount += r.Medium
		highCount += r.High
		criticalCount += r.Critical
	}

	assetID := results[0].AssetID
	assetVersionName := results[0].AssetVersionName

	return models.AssetRiskDistribution{
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		Label:            label,
		Low:              lowCount,
		Medium:           mediumCount,
		High:             highCount,
		Critical:         criticalCount,
	}
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

func getResultsInSeconds(results []time.Duration) float64 {
	resultsInSeconds := utils.Reduce(utils.Map(results, func(t time.Duration) float64 {
		return t.Abs().Seconds()
	}), func(acc, curr float64) float64 {
		return acc + curr
	}, 0.)
	return resultsInSeconds
}

func (c *httpController) GetAssetVersionRiskHistory(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")
	results, err := c.getAssetVersionRiskHistory(start, end, assetVersion)
	if err != nil {
		slog.Error("Error getting assetversion risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *httpController) getAssetVersionRiskHistory(start, end string, assetVersion models.AssetVersion) ([]models.AssetRiskHistory, error) {

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

	return c.statisticsService.GetAssetVersionRiskHistory(assetVersion.Name, assetVersion.AssetID, beginTime, endTime)
}

func (c *httpController) GetDependencyVulnAggregationStateAndChange(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	// extract the time from the query parameter
	compareTo := ctx.QueryParam("compareTo")
	results, err := c.getDependencyVulnAggregationStateAndChange(compareTo, assetVersion)

	if err != nil {
		slog.Error("Error getting dependencyVuln aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func aggregateDependencyVulnAggregationStateAndChange(results []DependencyVulnAggregationStateAndChange) DependencyVulnAggregationStateAndChange {
	// aggregate the results
	result := DependencyVulnAggregationStateAndChange{}
	for _, r := range results {
		result.Now.Fixed += r.Now.Fixed
		result.Now.Open += r.Now.Open

		result.Was.Fixed += r.Was.Fixed
		result.Was.Open += r.Was.Open
	}

	return result
}

func (c *httpController) getDependencyVulnAggregationStateAndChange(compareTo string, assetVersion models.AssetVersion) (DependencyVulnAggregationStateAndChange, error) {
	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		return DependencyVulnAggregationStateAndChange{}, errors.Wrap(err, "error parsing date")
	}

	return c.statisticsService.GetDependencyVulnAggregationStateAndChangeSince(assetVersion.Name, assetVersion.AssetID, calculateChangeTo)
}

func (c *httpController) GetNumberOfExploitableCVES(ctx core.Context) error {
	var cves []models.CVE
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, cves)
		}
	}
	//Query to find all CVE in the vulnerabilities for which an exploit exists
	err = c.assetVersionRepository.GetDB(nil).Raw("SELECT c.* FROM dependency_vulns d JOIN cves c ON d.cve_id = c.cve WHERE  EXISTS (SELECT id FROM exploits e WHERE d.cve_id = e.cve_id) AND d.asset_version_name = ?  AND d.state = 'open'  AND d.asset_id = ?;", assetVersion.Name, assetVersion.AssetID).Find(&cves).Error
	if err != nil {
		return ctx.JSON(500, cves)
	}

	return ctx.JSON(200, cves)
}
