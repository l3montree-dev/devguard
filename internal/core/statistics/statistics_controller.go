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

// get the risk distribution
func (c *httpController) GetOrgRiskDistribution(ctx core.Context) error {
	org := core.GetTenant(ctx)
	projects, err := c.projectRepository.GetByOrgID(org.ID)
	if err != nil {
		return err
	}

	results := make([][]models.AssetRiskDistribution, 0)
	// iterate over all projects and fetch the assets
	for _, project := range projects {
		projectResults, err := getAssetsRiskDistribution(project.ID, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	aggregatedResults := aggregateRiskDistribution(results)

	return ctx.JSON(200, aggregatedResults)
}
func (c *httpController) GetProjectRiskDistribution(ctx core.Context) error {
	project := core.GetProject(ctx)

	results, err := getAssetsRiskDistribution(project.ID, c)
	if err != nil {
		return err
	}

	// aggregate the results
	aggregatedResults := aggregateRiskDistribution(results)

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
func getAssetsRiskDistribution(projectID uuid.UUID, c *httpController) ([][]models.AssetRiskDistribution, error) {
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
		projectResults, err := getAssetsAverageFixingTime(project.ID, severity, c)
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
func (c *httpController) GetAverageProjectFixingTime(ctx core.Context) error {
	project := core.GetProject(ctx)
	severity := ctx.QueryParam("severity")
	err := checkSeverity(severity)
	if err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	results, err := getAssetsAverageFixingTime(project.ID, severity, c)
	if err != nil {
		return err
	}

	resultsInSeconds := getResultsInSeconds(results)

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": resultsInSeconds / float64(len(results)),
	})
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
func getAssetsAverageFixingTime(projectID uuid.UUID, severity string, c *httpController) ([]time.Duration, error) {
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
func getResultsInSeconds(results []time.Duration) float64 {
	resultsInSeconds := utils.Reduce(utils.Map(results, func(t time.Duration) float64 {
		return t.Abs().Seconds()
	}), func(acc, curr float64) float64 {
		return acc + curr
	}, 0.)
	return resultsInSeconds
}

// get the risk history
func (c *httpController) GetOrgRiskHistory(ctx core.Context) error {
	org := core.GetTenant(ctx)
	projects, err := c.projectRepository.GetByOrgID(org.ID)
	if err != nil {
		return err
	}

	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	results := make([]assetRiskHistory, 0)
	for _, project := range projects {
		projectResults, err := getAssetsRiskHistory(project.ID, start, end, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	return ctx.JSON(200, results)

}
func getAssetsRiskHistory(projectID uuid.UUID, start string, end string, c *httpController) ([]assetRiskHistory, error) {
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

	results, err := getAssetsRiskHistory(project.ID, start, end, c)
	if err != nil {
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

// get the flaw aggregation state and change
func (c *httpController) GetOrgFlawAggregationStateAndChange(ctx core.Context) error {
	org := core.GetTenant(ctx)
	compareTo := ctx.QueryParam("compareTo")

	projects, err := c.projectRepository.GetByOrgID(org.ID)
	if err != nil {
		return err
	}

	results := make([]flawAggregationStateAndChange, 0)
	for _, project := range projects {
		projectResults, err := getAssetsFlawAggregationStateAndChange(project.ID, compareTo, c)
		if err != nil {
			return err
		}
		results = append(results, projectResults...)
	}

	// aggregate the results
	result := aggregateFlawAggregationStateAndChange(results)
	return ctx.JSON(200, result)

}
func (c *httpController) GetProjectFlawAggregationStateAndChange(ctx core.Context) error {
	project := core.GetProject(ctx)
	compareTo := ctx.QueryParam("compareTo")

	results, err := getAssetsFlawAggregationStateAndChange(project.ID, compareTo, c)
	if err != nil {
		slog.Error("Error getting flaw aggregation state", "error", err)
		return ctx.JSON(500, nil)
	}
	// aggregate the results
	result := aggregateFlawAggregationStateAndChange(results)

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
func getAssetsFlawAggregationStateAndChange(projectID uuid.UUID, compareTo string, c *httpController) ([]flawAggregationStateAndChange, error) {
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
func aggregateFlawAggregationStateAndChange(results []flawAggregationStateAndChange) flawAggregationStateAndChange {
	// aggregate the results
	result := flawAggregationStateAndChange{}
	for _, r := range results {
		result.Now.Fixed += r.Now.Fixed
		result.Now.Open += r.Now.Open

		result.Was.Fixed += r.Was.Fixed
		result.Was.Open += r.Was.Open
	}

	return result
}

func (c *httpController) getFlawAggregationStateAndChange(compareTo string, asset models.Asset) (flawAggregationStateAndChange, error) {
	// parse the date
	calculateChangeTo, err := time.Parse(time.DateOnly, compareTo)
	if err != nil {
		return flawAggregationStateAndChange{}, errors.Wrap(err, "error parsing date")
	}

	return c.statisticsService.GetFlawAggregationStateAndChangeSince(asset.ID, calculateChangeTo)
}
