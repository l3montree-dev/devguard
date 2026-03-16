package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type StatisticsController struct {
	statisticsService      shared.StatisticsService
	statisticsRepository   shared.StatisticsRepository
	assetVersionRepository shared.AssetVersionRepository
}

func NewStatisticsController(statisticsService shared.StatisticsService, statisticsRepository shared.StatisticsRepository, assetVersionRepository shared.AssetVersionRepository) *StatisticsController {
	return &StatisticsController{
		statisticsService:      statisticsService,
		statisticsRepository:   statisticsRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

// @Summary Get average fixing times for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Success 200 {object} dtos.RemediationTimeAverages
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/average-fixing-time/ [get]
func (c *StatisticsController) GetAverageFixingTimes(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := ctx.QueryParam("artifactName")

	averages, err := c.statisticsRepository.AverageFixingTimes(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get average fixing time").WithInternal(err)
	}
	return ctx.JSON(200, averages)
}


// @Summary Get risk history for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Param start query string true "Start date (YYYY-MM-DD)"
// @Param end query string true "End date (YYYY-MM-DD)"
// @Success 200 {array} dtos.RiskHistoryDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/risk-history/ [get]
func (c *StatisticsController) GetArtifactRiskHistory(ctx shared.Context) error {
	artifact := ctx.QueryParam("artifactName")
	// get the start and end query params
	start := ctx.QueryParam("start")
	end := ctx.QueryParam("end")

	assetVersion := shared.GetAssetVersion(ctx)
	asset := shared.GetAsset(ctx)

	results, err := c.getArtifactRiskHistory(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, asset.ID, start, end)
	if err != nil {
		slog.Error("Error getting assetversion risk history", "error", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	dtoResults := make([]dtos.RiskHistoryDTO, 0, len(results))
	for _, r := range results {
		dtoResults = append(dtoResults, transformer.ArtifactRiskHistoryToDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

func (c *StatisticsController) getArtifactRiskHistory(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start, end string) ([]models.ArtifactRiskHistory, error) {

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

	return c.statisticsService.GetArtifactRiskHistory(ctx, artifactName, assetVersionName, assetID, beginTime, endTime)
}

// @Summary Get CVEs with known exploits for an asset
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} models.CVE
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/number-of-exploits/ [get]
func (c *StatisticsController) GetCVESWithKnownExploits(ctx shared.Context) error {
	var cves []models.CVE
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)

	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(ctx.Request().Context(), nil, asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	cves, err = c.statisticsRepository.CVESWithKnownExploitsInAssetVersion(ctx.Request().Context(), nil, assetVersion)
	if err != nil {
		return ctx.NoContent(500)
	}

	return ctx.JSON(200, cves)
}

// @Summary Get risk history for a release
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Param start query string true "Start date (YYYY-MM-DD)"
// @Param end query string true "End date (YYYY-MM-DD)"
// @Success 200 {array} dtos.RiskHistoryDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/stats/risk-history/ [get]
func (c *StatisticsController) GetReleaseRiskHistory(ctx shared.Context) error {
	// parse release id from param
	releaseIDParam := shared.GetParam(ctx, "releaseID")
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
	res, err := c.statisticsService.GetReleaseRiskHistory(ctx.Request().Context(), releaseID, beginTime, endTime)
	if err != nil {
		slog.Error("could not get release risk history", "err", err)
		return ctx.JSON(500, nil)
	}

	// convert to dto
	dtoResults := make([]dtos.RiskHistoryDTO, 0, len(res))
	for _, r := range res {
		dtoResults = append(dtoResults, transformer.ArtifactRiskHistoryToDTO(r))
	}

	return ctx.JSON(200, dtoResults)
}

// @Summary Get component risk distribution for an asset version
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Restrict results to a specific artifact"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/stats/component-risk/ [get]
func (c *StatisticsController) GetComponentRisk(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := ctx.QueryParam("artifactName")
	results, err := c.statisticsService.GetComponentRisk(ctx.Request().Context(), utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, results)
}

// @Summary Get average remediation times for a release
// @Tags Statistics
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} dtos.RemediationTimeAverages
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/stats/average-fixing-time/ [get]
func (c *StatisticsController) GetAverageReleaseFixingTime(ctx shared.Context) error {
	releaseIDParam := shared.GetParam(ctx, "releaseID")
	releaseID, err := uuid.Parse(releaseIDParam)
	if err != nil {
		return ctx.JSON(400, map[string]string{"error": "invalid release id"})
	}

	averages, err := c.statisticsService.GetRemediationTimeAveragesForRelease(ctx.Request().Context(), releaseID)
	if err != nil {
		slog.Error("could not get remediation time averages for release", "error", err)
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, averages)
}
