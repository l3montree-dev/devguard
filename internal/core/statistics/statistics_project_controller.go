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

	// get direct children
	childProjects, err := c.projectService.GetDirectChildProjects(project.ID)
	if err != nil {
		return errors.Wrap(err, "could not fetch child projects")
	}

	// get the risk distribution for this project
	assets, err := c.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[models.AssetRiskDistribution](10)
	for _, asset := range assets {
		group.Go(func() (models.AssetRiskDistribution, error) {
			return c.statisticsService.GetAssetRiskDistribution(asset.ID, asset.Name)
		})
	}

	projectResults, err := group.WaitAndCollect()
	if err != nil {
		return err
	}

	for _, childProject := range childProjects {
		res, err := c.getProjectRiskDistribution(childProject.ID)
		if err != nil {
			return errors.Wrap(err, "could not fetch assets by project id")
		}

		// aggregate the results
		projectResults = append(projectResults, aggregateRiskDistribution(res, childProject.ID, childProject.Name))
	}

	return ctx.JSON(200, projectResults)
}

func (c *httpController) getChildrenProjectIDs(projectID uuid.UUID) ([]uuid.UUID, error) {
	projects, err := c.projectService.RecursivelyGetChildProjects(projectID)
	if err != nil {
		return nil, err
	}

	projectIDs := make([]uuid.UUID, 0)
	for _, project := range projects {
		projectIDs = append(projectIDs, project.ID)
	}

	projectIDs = append(projectIDs, projectID)

	return projectIDs, nil
}

func (c *httpController) getProjectRiskDistribution(projectID uuid.UUID) ([]models.AssetRiskDistribution, error) {
	// fetch all assets
	projectIds, err := c.getChildrenProjectIDs(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch child projects")
	}

	assets, err := c.assetRepository.GetByProjectIDs(projectIds)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[models.AssetRiskDistribution](10)
	for _, asset := range assets {
		group.Go(func() (models.AssetRiskDistribution, error) {
			return c.statisticsService.GetAssetRiskDistribution(asset.ID, asset.Name)
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
	projectIDs, err := c.getChildrenProjectIDs(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch child projects")
	}

	// fetch all assets
	assets, err := c.assetRepository.GetByProjectIDs(projectIDs)
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

func (c *httpController) getAssetsRiskHistory(projectID uuid.UUID, start string, end string) ([]AssetRiskHistory, error) {
	// fetch all assets
	assets, err := c.assetRepository.GetByProjectID(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	errgroup := utils.ErrGroup[AssetRiskHistory](10)
	for _, asset := range assets {
		errgroup.Go(func() (AssetRiskHistory, error) {
			results, err := c.getAssetRiskHistory(start, end, asset)
			if err != nil {
				return AssetRiskHistory{}, err
			}
			return AssetRiskHistory{
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

	// get all child project histories
	childProjects, err := c.projectService.GetDirectChildProjects(project.ID)
	if err != nil {
		slog.Error("Error getting child projects", "error", err)
		return ctx.JSON(500, nil)
	}

	childResults := make([]ProjectRiskHistory, 0)
	// fetch the project risk history
	for _, childProject := range childProjects {
		r, err := c.getProjectRiskHistory(start, end, childProject)
		if err != nil {
			slog.Error("Error getting project risk history", "error", err)
			return ctx.JSON(500, nil)
		}

		childResults = append(childResults, ProjectRiskHistory{
			RiskHistory: r,
			Project:     childProject,
		})
	}

	// now we have two arrays. Combine them
	return ctx.JSON(200, utils.MergeUnrelated(childResults, results))
}

func (c *httpController) GetProjectVulnAggregationStateAndChange(ctx core.Context) error {
	project := core.GetProject(ctx)
	compareTo := ctx.QueryParam("compareTo")

	results, err := c.getProjectVulnAggregationStateAndChange(project.ID, compareTo)
	if err != nil {
		slog.Error("Error getting vuln aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}
	// aggregate the results
	result := aggregateVulnAggregationStateAndChange(results)

	return ctx.JSON(200, result)
}

func (c *httpController) getProjectVulnAggregationStateAndChange(projectID uuid.UUID, compareTo string) ([]VulnAggregationStateAndChange, error) {
	projectIDs, err := c.getChildrenProjectIDs(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch child projects")
	}

	errgroup := utils.ErrGroup[VulnAggregationStateAndChange](10)
	// get all assets
	assets, err := c.assetRepository.GetByProjectIDs(projectIDs)
	if err != nil {
		return nil, err
	}

	for _, asset := range assets {
		errgroup.Go(func() (VulnAggregationStateAndChange, error) {
			return c.getVulnAggregationStateAndChange(compareTo, asset)
		})
	}
	return errgroup.WaitAndCollect()
}
