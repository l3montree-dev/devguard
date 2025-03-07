package statistics

import (
	"fmt"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

func (c *httpController) GetOrgRiskDistribution(ctx core.Context) error {
	projects, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return err
	}

	results := make([]models.AssetRiskDistribution, 0)
	// iterate over all projects and fetch the assets
	for _, project := range projects {
		projectDistribution, err := c.getProjectRiskDistribution(project.ID)
		if err != nil {
			return err
		}
		results = append(results, aggregateRiskDistribution(projectDistribution, project.ID, project.Name))
	}

	return ctx.JSON(200, results)
}

// get the average fixing time
func (c *httpController) GetAverageOrgFixingTime(ctx core.Context) error {
	projects, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return err
	}

	severity := ctx.QueryParam("severity")
	err = checkSeverity(severity)
	if err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	results := make([]time.Duration, 0)
	for _, project := range projects {
		projectResults, err := c.getProjectAverageFixingTime(project.ID, severity)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
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

// get the risk history
func (c *httpController) GetOrgRiskHistory(ctx core.Context) error {
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	results, err := c.getOrgRiskHistory(ctx, start, end)
	if err != nil {
		return ctx.JSON(500, nil)
	}
	return ctx.JSON(200, results)

}

func (c *httpController) getOrgRiskHistory(ctx core.Context, start string, end string) ([]ProjectRiskHistory, error) {
	// fetch all projects
	projects, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch projects by org id")
	}

	errgroup := utils.ErrGroup[ProjectRiskHistory](10)
	for _, project := range projects {
		errgroup.Go(func() (ProjectRiskHistory, error) {
			results, err := c.getProjectRiskHistory(start, end, project)
			if err != nil {
				return ProjectRiskHistory{}, err
			}

			return ProjectRiskHistory{
				RiskHistory: results,
				Project:     project,
			}, nil
		})
	}

	return errgroup.WaitAndCollect()
}
func (c *httpController) getProjectRiskHistory(start, end string, project models.Project) ([]models.ProjectRiskHistory, error) {
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

	return c.statisticsService.GetProjectRiskHistory(project.ID, beginTime, endTime)
}

func (c *httpController) GetOrgDependencyVulnAggregationStateAndChange(ctx core.Context) error {
	compareTo := ctx.QueryParam("compareTo")

	projects, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return err
	}

	results := make([]DependencyVulnAggregationStateAndChange, 0)
	for _, project := range projects {
		projectResults, err := c.getProjectDependencyVulnAggregationStateAndChange(project.ID, compareTo)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	// aggregate the results
	result := aggregateDependencyVulnAggregationStateAndChange(results)
	return ctx.JSON(200, result)

}
