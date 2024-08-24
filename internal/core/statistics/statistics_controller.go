package statistics

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type statisticsService interface {
	GetComponentRisk(assetID uuid.UUID) (map[string]float64, error)
	GetAssetRiskDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error)
	GetAssetRiskHistory(assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error)
	GetFlawAggregationStateAndChangeSince(assetID uuid.UUID, calculateChangeTo time.Time) (flawAggregationStateAndChange, error)

	GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error)
	GetDependencyCountPerScanType(assetID uuid.UUID) (map[string]int, error)
	GetAverageFixingTime(assetID uuid.UUID, severity string) (time.Duration, error)
	UpdateAssetRiskAggregation(assetID uuid.UUID, begin time.Time, end time.Time) error
}

type httpController struct {
	statisticsService statisticsService
}

func NewHttpController(statisticsService statisticsService) *httpController {
	return &httpController{
		statisticsService: statisticsService,
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

func (c *httpController) AverageFixingTime(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	severity := ctx.QueryParam("severity")
	if severity == "" {
		slog.Warn("severity query parameter is required")
		return ctx.JSON(400, map[string]string{
			"error": "severity query parameter is required",
		})
	}

	// check the severity value
	if severity != "critical" && severity != "high" && severity != "medium" && severity != "low" {
		slog.Warn("severity query parameter must be one of critical, high, medium, low")
		return ctx.JSON(400, map[string]string{
			"error": "severity query parameter must be one of critical, high, medium, low",
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

func (c *httpController) GetAssetRiskHistory(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	if start == "" || end == "" {
		slog.Warn("start and end query parameters are required")
		return ctx.JSON(400, map[string]string{
			"error": "start and end query parameters are required",
		})
	}

	// parse the dates
	beginTime, err := time.Parse(time.DateOnly, start)
	if err != nil {
		slog.Warn("Error parsing begin date", "error", err)
		return ctx.JSON(400, map[string]string{
			"error": "begin query parameter must be a valid date",
		})
	}

	endTime, err := time.Parse(time.DateOnly, end)
	if err != nil {
		slog.Warn("Error parsing end date", "error", err)
		return ctx.JSON(400, map[string]string{
			"error": "end query parameter must be a valid date",
		})
	}

	results, err := c.statisticsService.GetAssetRiskHistory(asset.ID, beginTime, endTime)

	if err != nil {
		slog.Error("Error getting asset risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetFlawAggregationStateAndChange(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	// extract the time from the query parameter
	compareTo := ctx.QueryParam("compareTo")
	if compareTo == "" {
		slog.Warn("compareTo query parameter is required")
		return ctx.JSON(400, map[string]string{
			"error": "compareTo query parameter is required",
		})
	}

	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		slog.Warn("Error parsing date", "error", err)
		return ctx.JSON(400, map[string]string{
			"error": "compareTo query parameter must be a valid date",
		})
	}

	results, err := c.statisticsService.GetFlawAggregationStateAndChangeSince(asset.ID, calculateChangeTo)

	if err != nil {
		slog.Error("Error getting flaw aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}
