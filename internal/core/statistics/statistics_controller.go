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
	GetFlawAggregationStateAndChangeSince(assetID uuid.UUID, calculateChangeTo time.Time) (flawAggregationStateAndChange, error)

	GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error)
	GetDependencyCountPerScanType(assetID uuid.UUID) (map[string]int, error)
	GetAverageFixingTime(assetID uuid.UUID, severity string) (time.Duration, error)
	UpdateAssetRiskAggregation(assetID uuid.UUID, begin time.Time, end time.Time) error
}

type httpController struct {
	statisticsService statisticsService
	assetRepository   assetRepository
}

func NewHttpController(statisticsService statisticsService, assetRepository assetRepository) *httpController {
	return &httpController{
		statisticsService: statisticsService,
		assetRepository:   assetRepository,
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

func (c *httpController) GetProjectRiskDistribution(ctx core.Context) error {
	project := core.GetProject(ctx)
	// fetch all assets
	assets, err := c.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[[]models.AssetRiskDistribution](10)
	for _, asset := range assets {
		group.Go(func() ([]models.AssetRiskDistribution, error) {
			return c.statisticsService.GetAssetRiskDistribution(asset.ID)
		})
	}

	results, err := group.WaitAndCollect()
	if err != nil {
		return err
	}

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

	return ctx.JSON(200, aggregatedResults)
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

func (c *httpController) GetAverageProjectFixingTime(ctx core.Context) error {
	project := core.GetProject(ctx)
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

	assets, err := c.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	// get all assets and iterate over them
	errgroup := utils.ErrGroup[time.Duration](10)
	for _, asset := range assets {
		errgroup.Go(func() (time.Duration, error) {
			return c.statisticsService.GetAverageFixingTime(asset.ID, severity)
		})
	}

	results, err := errgroup.WaitAndCollect()
	if err != nil {
		return err
	}

	resultsInSeconds := utils.Reduce(utils.Map(results, func(t time.Duration) float64 {
		return t.Abs().Seconds()
	}), func(acc, curr float64) float64 {
		return acc + curr
	}, 0.)

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": resultsInSeconds / float64(len(results)),
	})
}

func (c *httpController) GetProjectRiskHistory(ctx core.Context) error {
	// fetch all assets from the project
	project := core.GetProject(ctx)
	assets, err := c.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	// iterate over all assets and fetch the histories.
	// set the limit to 10
	errgroup := utils.ErrGroup[assetRiskHistory](10)
	for _, asset := range assets {
		errgroup.Go(func() (assetRiskHistory, error) {
			results, err := c.getAssetRiskHistory(start, end, asset)
			if err != nil {
				return assetRiskHistory{}, err
			}

			return assetRiskHistory{
				RiskHistory: results,
				Asset:       asset,
			}, nil
		})
	}

	results, err := errgroup.WaitAndCollect()

	if err != nil {
		slog.Error("Error getting project risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
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

func (c *httpController) GetProjectFlawAggregationStateAndChange(ctx core.Context) error {
	project := core.GetProject(ctx)
	compareTo := ctx.QueryParam("compareTo")

	errgroup := utils.ErrGroup[flawAggregationStateAndChange](10)
	// get all assets
	assets, err := c.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	for _, asset := range assets {
		errgroup.Go(func() (flawAggregationStateAndChange, error) {
			return c.getFlawAggregationStateAndChange(compareTo, asset)
		})
	}

	results, err := errgroup.WaitAndCollect()
	if err != nil {
		return err
	}
	// aggregate the results
	result := flawAggregationStateAndChange{}
	for _, r := range results {
		result.Now.Fixed += r.Now.Fixed
		result.Now.Open += r.Now.Open

		result.Was.Fixed += r.Was.Fixed
		result.Was.Open += r.Was.Open
	}

	return ctx.JSON(200, result)
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

func (c *httpController) getFlawAggregationStateAndChange(compareTo string, asset models.Asset) (flawAggregationStateAndChange, error) {
	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		return flawAggregationStateAndChange{}, errors.Wrap(err, "error parsing date")
	}

	return c.statisticsService.GetFlawAggregationStateAndChangeSince(asset.ID, calculateChangeTo)
}
