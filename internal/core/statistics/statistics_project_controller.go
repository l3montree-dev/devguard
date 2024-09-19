package statistics

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

func (c *httpController) GetProjectRiskDistribution(ctx core.Context) error {
	project := core.GetProject(ctx)

	results, err := c.getProjectRiskDistribution(project.ID)
	if err != nil {
		return err
	}

	// aggregate the results
	aggregatedResults := aggregateRiskDistribution(results)

	return ctx.JSON(200, aggregatedResults)
}

func (c *httpController) getProjectRiskDistribution(projectID uuid.UUID) ([][]models.AssetRiskDistribution, error) {
	// fetch all assets
	assets, err := c.assetRepository.GetByProjectID(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[[]models.AssetRiskDistribution](10)
	for _, asset := range assets {
		group.Go(func() ([]models.AssetRiskDistribution, error) {
			return c.statisticsService.GetAssetRiskDistribution(asset.ID)
		})
	}

	return group.WaitAndCollect()
}

func (c *httpController) GetAverageProjectFixingTime(ctx core.Context) error {
	project := core.GetProject(ctx)
	severity := ctx.QueryParam("severity")
	err := checkSeverity(severity)
	if err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	results, err := c.getProjectAverageFixingTime(project.ID, severity)
	if err != nil {
		return err
	}

	resultsInSeconds := getResultsInSeconds(results)

	if len(results) == 0 {
		return ctx.JSON(200, map[string]float64{
			"averageFixingTimeSeconds": 0,
		})
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": resultsInSeconds / float64(len(results)),
	})
}

func (c *httpController) getProjectAverageFixingTime(projectID uuid.UUID, severity string) ([]time.Duration, error) {
	// fetch all assets
	assets, err := c.assetRepository.GetByProjectID(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	// get all assets and iterate over them
	errgroup := utils.ErrGroup[time.Duration](10)
	for _, asset := range assets {
		errgroup.Go(func() (time.Duration, error) {
			return c.statisticsService.GetAverageFixingTime(asset.ID, severity)
		})
	}

	return errgroup.WaitAndCollect()
}

func (c *httpController) getAssetsRiskHistory(projectID uuid.UUID, start string, end string) ([]assetRiskHistory, error) {
	// fetch all assets
	assets, err := c.assetRepository.GetByProjectID(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

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

	return errgroup.WaitAndCollect()
}
func (c *httpController) GetProjectRiskHistory(ctx core.Context) error {
	// fetch all assets from the project
	project := core.GetProject(ctx)

	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	results, err := c.getAssetsRiskHistory(project.ID, start, end)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *httpController) GetProjectFlawAggregationStateAndChange(ctx core.Context) error {
	project := core.GetProject(ctx)
	compareTo := ctx.QueryParam("compareTo")

	results, err := c.getProjectFlawAggregationStateAndChange(project.ID, compareTo)
	if err != nil {
		slog.Error("Error getting flaw aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}
	// aggregate the results
	result := aggregateFlawAggregationStateAndChange(results)

	return ctx.JSON(200, result)
}

func (c *httpController) getProjectFlawAggregationStateAndChange(projectID uuid.UUID, compareTo string) ([]flawAggregationStateAndChange, error) {
	errgroup := utils.ErrGroup[flawAggregationStateAndChange](10)
	// get all assets
	assets, err := c.assetRepository.GetByProjectID(projectID)
	if err != nil {
		return nil, err
	}

	for _, asset := range assets {
		errgroup.Go(func() (flawAggregationStateAndChange, error) {
			return c.getFlawAggregationStateAndChange(compareTo, asset)
		})
	}
	return errgroup.WaitAndCollect()
}
