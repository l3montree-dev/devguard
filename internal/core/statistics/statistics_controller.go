package statistics

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type statisticsService interface {
	GetAssetFlawsStatistics(assetID uuid.UUID) ([]models.AssetRiskSummary, error)
	GetAssetCombinedDependencies(assetID uuid.UUID) ([]models.AssetCombinedDependencies, error)
	GetAssetFlawsDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error)
	GetAssetFlaws(assetID uuid.UUID) ([]models.AssetFlaws, models.AssetFlawsStateStatistics, []models.AssetComponents, []models.AssetComponents, []models.FlawEventWithFlawName, error)

	UpdateAssetRecentRisks(assetID uuid.UUID, begin time.Time, end time.Time) error
	GetAssetRecentRisksByAssetId(assetID uuid.UUID) ([]models.AssetRecentRisks, error)
}

type httpController struct {
	statisticsService statisticsService
}

func NewHttpController(statisticsService statisticsService) *httpController {
	return &httpController{
		statisticsService: statisticsService,
	}
}

func (c *httpController) Overview(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	t := time.Now().AddDate(0, 0, -30)
	err := c.statisticsService.UpdateAssetRecentRisks(asset.ID, t, time.Now())
	if err != nil {
		return fmt.Errorf("Error updating asset risks: %v", err)
	}

	dependencies, err := c.statisticsService.GetAssetCombinedDependencies(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset dependencies: %v", err)
	}
	risksSummary, err := c.statisticsService.GetAssetFlawsStatistics(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset risk summary: %v", err)
	}
	riskDistribution, err := c.statisticsService.GetAssetFlawsDistribution(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset risk distribution: %v", err)
	}

	risks, err := c.statisticsService.GetAssetRecentRisksByAssetId(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset risks: %v", err)
	}

	flaws, flawsStateStatistics, highestDamagedPackages, components, details, err := c.statisticsService.GetAssetFlaws(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset flaws: %v", err)
	}

	var totalDependenciesNumber int64 = 0
	totalCriticalDependenciesNumber := len(risksSummary)

	for _, dependency := range dependencies {
		totalDependenciesNumber += dependency.CountDependencies
	}

	overview := models.AssetOverview{
		TotalDependencies:         int(totalDependenciesNumber),
		TotalCriticalDependencies: totalCriticalDependenciesNumber,
		CombinedDependencies:      dependencies,
		RiskSummary:               risksSummary,
		RiskDistribution:          riskDistribution,
		RecentRisks:               risks,
		Flaws:                     flaws,
		FlawsStateStatistics:      flawsStateStatistics,
		HighestDamagedPackages:    highestDamagedPackages,
		Components:                components,
		FlawEvents:                details,
	}

	return ctx.JSON(200, overviewToDto(overview))
}
