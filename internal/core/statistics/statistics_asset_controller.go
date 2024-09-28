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
	GetComponentRisk(assetID uuid.UUID) (map[string]float64, error)
	GetAssetRiskDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error)
	GetAssetRiskHistory(assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error)
	GetFlawAggregationStateAndChangeSince(assetID uuid.UUID, calculateChangeTo time.Time) (FlawAggregationStateAndChange, error)

	GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error)
	GetDependencyCountPerScanType(assetID uuid.UUID) (map[string]int, error)
	GetAverageFixingTime(assetID uuid.UUID, severity string) (time.Duration, error)
	UpdateAssetRiskAggregation(assetID uuid.UUID, start time.Time, end time.Time, updateProject bool) error

	GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error)
}

type projectRepository interface {
	GetByOrgID(organizationID uuid.UUID) ([]models.Project, error)
}

type httpController struct {
	statisticsService statisticsService
	assetRepository   assetRepository
	projectRepository projectRepository
}

func NewHttpController(statisticsService statisticsService, assetRepository assetRepository, projectRepository projectRepository) *httpController {
	return &httpController{
		statisticsService: statisticsService,
		assetRepository:   assetRepository,
		projectRepository: projectRepository,
	}
}

func (c *httpController) GetComponentRisk(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetComponentRisk(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetDependencyCountPerScanType(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetDependencyCountPerScanType(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetFlawCountByScannerId(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetFlawCountByScannerId(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAssetRiskDistribution(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetAssetRiskDistribution(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAverageAssetFixingTime(ctx core.Context) error {
	asset := core.GetAsset(ctx)
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

	duration, err := c.statisticsService.GetAverageFixingTime(asset.ID, severity)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": duration.Abs().Seconds(),
	})
}

func aggregateRiskDistribution(results [][]models.AssetRiskDistribution) []models.AssetRiskDistribution {
	// aggregate the results
	resultMap := make(map[string]map[string]int64)
	for _, r := range utils.Flat(results) {
		if _, ok := resultMap[r.ScannerID]; !ok {
			// no scanner result exists yet
			m := map[string]int64{
				"low":      0,
				"medium":   0,
				"high":     0,
				"critical": 0,
			}
			resultMap[r.ScannerID] = m
		}

		resultMap[r.ScannerID][r.Severity] += r.Count
	}

	// create arrays based on the result map
	aggregatedResults := make([]models.AssetRiskDistribution, 0)
	for scannerId, severityMap := range resultMap {
		for severity, count := range severityMap {
			aggregatedResults = append(aggregatedResults, models.AssetRiskDistribution{
				ScannerID: scannerId,
				Severity:  severity,
				Count:     count,
			})
		}
	}
	return aggregatedResults
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

func (c *httpController) GetAssetRiskHistory(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")
	results, err := c.getAssetRiskHistory(start, end, asset)
	if err != nil {
		slog.Error("Error getting asset risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *httpController) getAssetRiskHistory(start, end string, asset models.Asset) ([]models.AssetRiskHistory, error) {

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

	return c.statisticsService.GetAssetRiskHistory(asset.ID, beginTime, endTime)
}

func (c *httpController) GetFlawAggregationStateAndChange(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// extract the time from the query parameter
	compareTo := ctx.QueryParam("compareTo")
	results, err := c.getFlawAggregationStateAndChange(compareTo, asset)

	if err != nil {
		slog.Error("Error getting flaw aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func aggregateFlawAggregationStateAndChange(results []FlawAggregationStateAndChange) FlawAggregationStateAndChange {
	// aggregate the results
	result := FlawAggregationStateAndChange{}
	for _, r := range results {
		result.Now.Fixed += r.Now.Fixed
		result.Now.Open += r.Now.Open

		result.Was.Fixed += r.Was.Fixed
		result.Was.Open += r.Was.Open
	}

	return result
}

func (c *httpController) getFlawAggregationStateAndChange(compareTo string, asset models.Asset) (FlawAggregationStateAndChange, error) {
	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		return FlawAggregationStateAndChange{}, errors.Wrap(err, "error parsing date")
	}

	return c.statisticsService.GetFlawAggregationStateAndChangeSince(asset.ID, calculateChangeTo)
}
