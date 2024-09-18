package statistics

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

func (c *httpController) GetOrgRiskDistribution(ctx core.Context) error {
	org := core.GetTenant(ctx)
	projects, err := c.projectRepository.GetByOrgID(org.ID)
	if err != nil {
		return err
	}

	results := make([][]models.AssetRiskDistribution, 0)
	// iterate over all projects and fetch the assets
	for _, project := range projects {
		projectResults, err := getProjectRiskDistribution(project.ID, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	aggregatedResults := aggregateRiskDistribution(results)

	return ctx.JSON(200, aggregatedResults)
}

// get the average fixing time
func (c *httpController) GetAverageOrgFixingTime(ctx core.Context) error {
	org := core.GetTenant(ctx)
	projects, err := c.projectRepository.GetByOrgID(org.ID)
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
		projectResults, err := getProjectAverageFixingTime(project.ID, severity, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}
	resultsInSeconds := getResultsInSeconds(results)

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": resultsInSeconds / float64(len(results)),
	})
}

// get the risk history
func (c *httpController) GetOrgRiskHistory(ctx core.Context) error {
	org := core.GetTenant(ctx)
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	results, err := getOrgRiskHistory(org.ID, start, end, c)
	if err != nil {
		return ctx.JSON(500, nil)
	}
	return ctx.JSON(200, results)

}

func getOrgRiskHistory(orgID uuid.UUID, start string, end string, c *httpController) ([]projectRiskHistory, error) {
	// fetch all projects
	projects, err := c.projectRepository.GetByOrgID(orgID)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch projects by org id")
	}

	errgroup := utils.ErrGroup[projectRiskHistory](10)
	for _, project := range projects {
		errgroup.Go(func() (projectRiskHistory, error) {
			results, err := c.getProjectRiskHistory(start, end, project)
			if err != nil {
				return projectRiskHistory{}, err
			}

			return projectRiskHistory{
				RiskHistory: results,
				Project:     project,
			}, nil
		})
	}

	return errgroup.WaitAndCollect()
}

func (c *httpController) GetOrgFlawAggregationStateAndChange(ctx core.Context) error {
	org := core.GetTenant(ctx)
	compareTo := ctx.QueryParam("compareTo")

	projects, err := c.projectRepository.GetByOrgID(org.ID)
	if err != nil {
		return err
	}

	results := make([]flawAggregationStateAndChange, 0)
	for _, project := range projects {
		projectResults, err := getProjectFlawAggregationStateAndChange(project.ID, compareTo, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	// aggregate the results
	result := aggregateFlawAggregationStateAndChange(results)
	return ctx.JSON(200, result)

}
