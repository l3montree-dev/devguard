package statistics

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type statisticsService interface {
	GetAssetFlawsStatistics(asset_ID string) ([]models.AssetRiskSummary, error)
	GetAssetCombinedDependencies(asset_ID string) ([]models.AssetCombinedDependencies, error)
	GetAssetFlawsDistribution(asset_ID string) ([]models.AssetRiskDistribution, error)
	GetAssetFlaws(assetID uuid.UUID) ([]models.AssetFlaws, models.AssetFlawsStateStatistics, []models.AssetComponents, []models.AssetComponents, []models.FlawEventWithFlawName, error)

	UpdateAssetRecentRisks(assetID uuid.UUID, begin time.Time, end time.Time) error
	GetAssetRecentRisksByAssetId(assetID uuid.UUID) ([]models.AssetRecentRisks, error)
}

type httpController struct {
	assetService statisticsService
}

func NewHttpController(assetService statisticsService) *httpController {
	return &httpController{
		assetService: assetService,
	}
}

func (c *httpController) Overview(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	t := time.Now().AddDate(0, 0, -30)
	err := c.assetService.UpdateAssetRecentRisks(asset.ID, t, time.Now())
	if err != nil {
		return fmt.Errorf("Error updating asset risks: %v", err)
	}

	assetDependencies, err := c.assetService.GetAssetCombinedDependencies(asset.ID.String())
	if err != nil {
		return fmt.Errorf("Error getting asset dependencies: %v", err)
	}
	assetRisksSummary, err := c.assetService.GetAssetFlawsStatistics(asset.ID.String())
	if err != nil {
		return fmt.Errorf("Error getting asset risk summary: %v", err)
	}
	assetRiskDistribution, err := c.assetService.GetAssetFlawsDistribution(asset.ID.String())
	if err != nil {
		return fmt.Errorf("Error getting asset risk distribution: %v", err)
	}

	assetRisks, err := c.assetService.GetAssetRecentRisksByAssetId(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset risks: %v", err)
	}

	assetFlaws, assetFlawsStateStatistics, assetHighestDamagedPackages, assetComponents, assetDetails, err := c.assetService.GetAssetFlaws(asset.ID)
	if err != nil {
		return fmt.Errorf("Error getting asset flaws: %v", err)
	}

	var totalDependenciesNumber int64 = 0
	totalCriticalDependenciesNumber := len(assetRisksSummary)

	for _, dependency := range assetDependencies {
		totalDependenciesNumber += dependency.CountDependencies
	}

	overview := models.Overview{
		TotalDependencies:           int(totalDependenciesNumber),
		TotalCriticalDependencies:   totalCriticalDependenciesNumber,
		AssetCombinedDependencies:   assetDependencies,
		AssetRiskSummary:            assetRisksSummary,
		AssetRiskDistribution:       assetRiskDistribution,
		AssetRecentRisks:            assetRisks,
		AssetFlaws:                  assetFlaws,
		AssetFlawsStateStatistics:   assetFlawsStateStatistics,
		AssetHighestDamagedPackages: assetHighestDamagedPackages,
		AssetComponents:             assetComponents,
		FlawEvents:                  assetDetails,
	}

	return ctx.JSON(200, OverviewToDto(overview))
}
