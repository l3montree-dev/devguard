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
	GetAssetRiskDistribution(assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)
	GetAssetRiskHistory(assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error)
	GetVulnAggregationStateAndChangeSince(assetID uuid.UUID, calculateChangeTo time.Time) (VulnAggregationStateAndChange, error)

	GetVulnCountByScannerId(assetID uuid.UUID) (map[string]int, error)
	GetDependencyCountPerscanner(assetID uuid.UUID) (map[string]int, error)
	GetAverageFixingTime(assetID uuid.UUID, severity string) (time.Duration, error)
	UpdateAssetRiskAggregation(assetID uuid.UUID, start time.Time, end time.Time, updateProject bool) error

	GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error)
}

type projectService interface {
	ListAllowedProjects(c core.Context) ([]models.Project, error)
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error)
}

type httpController struct {
	statisticsService statisticsService
	assetRepository   assetRepository
	projectService    projectService
}

func NewHttpController(statisticsService statisticsService, assetRepository assetRepository, projectService projectService) *httpController {
	return &httpController{
		statisticsService: statisticsService,
		assetRepository:   assetRepository,
		projectService:    projectService,
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

func (c *httpController) GetDependencyCountPerScanner(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetDependencyCountPerscanner(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetVulnCountByScannerId(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetVulnCountByScannerId(asset.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetAssetRiskDistribution(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	results, err := c.statisticsService.GetAssetRiskDistribution(asset.ID, asset.Name)

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

	return models.AssetRiskDistribution{
		ID:       id,
		Label:    label,
		Low:      lowCount,
		Medium:   mediumCount,
		High:     highCount,
		Critical: criticalCount,
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

func (c *httpController) GetVulnAggregationStateAndChange(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// extract the time from the query parameter
	compareTo := ctx.QueryParam("compareTo")
	results, err := c.getVulnAggregationStateAndChange(compareTo, asset)

	if err != nil {
		slog.Error("Error getting vuln aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func aggregateVulnAggregationStateAndChange(results []VulnAggregationStateAndChange) VulnAggregationStateAndChange {
	// aggregate the results
	result := VulnAggregationStateAndChange{}
	for _, r := range results {
		result.Now.Fixed += r.Now.Fixed
		result.Now.Open += r.Now.Open

		result.Was.Fixed += r.Was.Fixed
		result.Was.Open += r.Was.Open
	}

	return result
}

func (c *httpController) getVulnAggregationStateAndChange(compareTo string, asset models.Asset) (VulnAggregationStateAndChange, error) {
	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		return VulnAggregationStateAndChange{}, errors.Wrap(err, "error parsing date")
	}

	return c.statisticsService.GetVulnAggregationStateAndChangeSince(asset.ID, calculateChangeTo)
}
