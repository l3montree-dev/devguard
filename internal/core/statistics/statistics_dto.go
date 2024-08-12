package statistics

import (
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetOverviewDTO struct {
	TotalDependencies           int                                `json:"totalDependenciesNumber"`
	TotalCriticalDependencies   int                                `json:"criticalDependenciesNumber"`
	AssetCombinedDependencies   []models.AssetCombinedDependencies `json:"assetCombinedDependencies"`
	AssetRiskSummary            []models.AssetRiskSummary          `json:"assetRiskSummary"`
	AssetRiskDistribution       []models.AssetRiskDistribution     `json:"assetRiskDistribution"`
	AssetRecentRisks            []models.AssetRecentRisks          `json:"assetRisks"`
	AssetFlaws                  []models.AssetFlaws                `json:"assetFlaws"`
	AssetFlawsStateStatistics   models.AssetFlawsStateStatistics   `json:"assetFlawsStateStatistics"`
	AssetHighestDamagedPackages []models.AssetComponents           `json:"assetHighestDamagedPackages"`
	AssetComponents             []models.AssetComponents           `json:"assetComponents"`
	FlawEvents                  []flawEventWithFlawNameDTO         `json:"flawEvents"`
}

type flawEventWithFlawNameDTO struct {
	flaw.FlawEventDTO
	FlawName string `json:"flawName"`
}

func overviewToDto(o models.AssetOverview) assetOverviewDTO {
	flawEvents := o.FlawEvents
	flawEventDTO := make([]flawEventWithFlawNameDTO, len(o.FlawEvents))
	for i, flawEvent := range flawEvents {
		flawEventDTO[i] = flawEventToDto(flawEvent)
	}

	return assetOverviewDTO{
		TotalDependencies:           o.TotalDependencies,
		TotalCriticalDependencies:   o.TotalCriticalDependencies,
		AssetCombinedDependencies:   o.CombinedDependencies,
		AssetRiskSummary:            o.RiskSummary,
		AssetRiskDistribution:       o.RiskDistribution,
		AssetRecentRisks:            o.RecentRisks,
		AssetFlaws:                  o.Flaws,
		AssetFlawsStateStatistics:   o.FlawsStateStatistics,
		AssetHighestDamagedPackages: o.HighestDamagedPackages,
		AssetComponents:             o.Components,
		FlawEvents:                  flawEventDTO,
	}
}

func flawEventToDto(flawEvent models.FlawEventWithFlawName) flawEventWithFlawNameDTO {
	return struct {
		flaw.FlawEventDTO
		FlawName string `json:"flawName"`
	}{
		FlawEventDTO: flaw.FlawEventDTO{
			ID:                flawEvent.ID,
			Type:              flawEvent.Type,
			FlawID:            flawEvent.FlawID,
			UserID:            flawEvent.UserID,
			Justification:     flawEvent.Justification,
			ArbitraryJsonData: flawEvent.GetArbitraryJsonData(),
			CreatedAt:         flawEvent.CreatedAt,
		},
		FlawName: flawEvent.FlawName,
	}
}
