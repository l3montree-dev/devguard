package statistics

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/pkg/errors"
)

type httpController struct {
	statisticsService      core.StatisticsService
	statisticsRepository   core.StatisticsRepository
	assetVersionRepository core.AssetVersionRepository
	assetRepository        core.AssetRepository
	projectService         core.ProjectService
}

func NewHTTPController(statisticsService core.StatisticsService, statisticsRepository core.StatisticsRepository, assetRepository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, projectService core.ProjectService) *httpController {
	return &httpController{
		statisticsService:      statisticsService,
		statisticsRepository:   statisticsRepository,
		assetVersionRepository: assetVersionRepository,
		projectService:         projectService,
		assetRepository:        assetRepository,
	}
}

func (c *httpController) GetAverageFixingTime(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	severity := ctx.QueryParam("severity")
	if severity == "" {
		slog.Warn("severity query parameter is required")
		return ctx.JSON(400, map[string]string{
			"error": "severity query parameter is required",
		})
	}

	artifact := core.GetArtifact(ctx)

	// check the severity value
	if err := checkSeverity(severity); err != nil {
		return ctx.JSON(400, map[string]string{
			"error": err.Error(),
		})
	}

	duration, err := c.statisticsService.GetAverageFixingTime(artifact.ArtifactName, assetVersion.Name, assetVersion.AssetID, severity)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, map[string]float64{
		"averageFixingTimeSeconds": duration.Abs().Seconds(),
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

func (c *httpController) GetArtifactRiskHistory(ctx core.Context) error {
	artifact := core.GetArtifact(ctx)
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")
	results, err := c.getArtifactRiskHistory(start, end, artifact)
	if err != nil {
		slog.Error("Error getting assetversion risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	var dtoResults []RiskHistoryDTO
	for _, r := range results {
		dtoResults = append(dtoResults, fromModelToRiskHistoryDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

func (c *httpController) getArtifactRiskHistory(start, end string, artifact models.Artifact) ([]models.ArtifactRiskHistory, error) {

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

	return c.statisticsService.GetArtifactRiskHistory(artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID, beginTime, endTime)
}

func (c *httpController) GetCVESWithKnownExploits(ctx core.Context) error {
	var cves []models.CVE
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	cves, err = c.statisticsRepository.CVESWithKnownExploitsInAssetVersion(assetVersion)
	if err != nil {
		return ctx.NoContent(500)
	}

	return ctx.JSON(200, cves)
}

// GetReleaseRiskHistory returns aggregated artifact risk history for a given release
func (c *httpController) GetReleaseRiskHistory(ctx core.Context) error {
	// parse release id from param
	releaseIDParam := core.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")
	if start == "" || end == "" {
		return ctx.JSON(400, map[string]string{"error": "start and end query parameters are required"})
	}
	beginTime, err := time.Parse(time.DateOnly, start)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid start date"})
	}
	endTime, err := time.Parse(time.DateOnly, end)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid end date"})
	}

	// delegate to service
	res, err := c.statisticsService.GetReleaseRiskHistory(releaseID, beginTime, endTime)
	if err != nil {
		slog.Error("could not get release risk history", "err", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	var dtoResults []RiskHistoryDTO
	for _, r := range res {
		dtoResults = append(dtoResults, fromModelToRiskHistoryDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

func (c *httpController) GetComponentRisk(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	artifact := core.GetArtifact(ctx)
	results, err := c.statisticsService.GetComponentRisk(artifact.ArtifactName, assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

// GetAverageReleaseFixingTime returns the average fixing time (seconds) for a release across all included artifacts
func (c *httpController) GetAverageReleaseFixingTime(ctx core.Context) error {
	releaseIDParam := core.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	severity := ctx.QueryParam("severity")
	if severity == "" {
		return ctx.JSON(400, map[string]string{"error": "severity query parameter is required"})
	}
	if err := checkSeverity(severity); err != nil {
		return ctx.JSON(400, map[string]string{"error": err.Error()})
	}

	duration, err := c.statisticsService.GetAverageFixingTimeForRelease(releaseID, severity)
	if err != nil {
		slog.Error("could not compute average fixing time for release", "err", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, map[string]float64{"averageFixingTimeSeconds": duration.Abs().Seconds()})
}
