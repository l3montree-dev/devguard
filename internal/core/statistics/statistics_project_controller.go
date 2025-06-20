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
	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectID(project.ID)
	if err != nil {
		return errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[models.AssetRiskDistribution](10)
	for _, assetVersion := range assetVersions {
		group.Go(func() (models.AssetRiskDistribution, error) {
			// get the corresponding asset
			asset, err := c.assetRepository.Read(assetVersion.AssetID)
			if err != nil {
				return models.AssetRiskDistribution{}, errors.Wrap(err, "could not fetch asset by id")
			}

			return c.statisticsService.GetAssetVersionRiskDistribution(assetVersion.Name, assetVersion.AssetID, asset.Name)
		})
	}

	projectResults, err := group.WaitAndCollect()
	if err != nil {
		return errors.Wrap(err, "could not fetch risk distribution")
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
	projectIDs, err := c.getChildrenProjectIDs(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch child projects")
	}

	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectIDs(projectIDs)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	group := utils.ErrGroup[models.AssetRiskDistribution](10)
	for _, assetVersion := range assetVersions {
		group.Go(func() (models.AssetRiskDistribution, error) {
			// get the corresponding asset
			asset, err := c.assetRepository.Read(assetVersion.AssetID)
			if err != nil {
				return models.AssetRiskDistribution{}, errors.Wrap(err, "could not fetch asset by id")
			}

			return c.statisticsService.GetAssetVersionRiskDistribution(assetVersion.Name, assetVersion.AssetID, asset.Name)
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
	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectIDs(projectIDs)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	// get all assets and iterate over them
	errgroup := utils.ErrGroup[time.Duration](10)
	for _, assetVersion := range assetVersions {
		errgroup.Go(func() (time.Duration, error) {
			return c.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, severity)
		})
	}

	return errgroup.WaitAndCollect()
}

func (c *httpController) getAssetVersionsRiskHistory(projectID uuid.UUID, start string, end string) ([]AssetRiskHistory, error) {
	// fetch all assets
	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectID(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch assets by project id")
	}

	errgroup := utils.ErrGroup[AssetRiskHistory](10)
	for _, assetVersion := range assetVersions {
		errgroup.Go(func() (AssetRiskHistory, error) {
			results, err := c.getAssetVersionRiskHistory(start, end, assetVersion)
			if err != nil {
				return AssetRiskHistory{}, err
			}
			asset, err := c.assetRepository.Read(assetVersion.AssetID)
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

	results, err := c.getAssetVersionsRiskHistory(project.ID, start, end)
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

func (c *httpController) GetProjectDependencyVulnAggregationStateAndChange(ctx core.Context) error {
	project := core.GetProject(ctx)
	compareTo := ctx.QueryParam("compareTo")

	results, err := c.getProjectDependencyVulnAggregationStateAndChange(project.ID, compareTo)
	if err != nil {
		slog.Error("Error getting dependencyVuln aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}
	// aggregate the results
	result := aggregateDependencyVulnAggregationStateAndChange(results)

	return ctx.JSON(200, result)
}

func (c *httpController) getProjectDependencyVulnAggregationStateAndChange(projectID uuid.UUID, compareTo string) ([]DependencyVulnAggregationStateAndChange, error) {
	projectIDs, err := c.getChildrenProjectIDs(projectID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch child projects")
	}

	errgroup := utils.ErrGroup[DependencyVulnAggregationStateAndChange](10)
	// get all assets
	assets, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectIDs(projectIDs)
	if err != nil {
		return nil, err
	}

	for _, asset := range assets {
		errgroup.Go(func() (DependencyVulnAggregationStateAndChange, error) {
			return c.getDependencyVulnAggregationStateAndChange(compareTo, asset)
		})
	}
	return errgroup.WaitAndCollect()
}
