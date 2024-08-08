package statistics

import (
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type OverviewDTO struct {
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
	FlawEvents                  []FlawEventWithFlawNameDTO         `json:"flawEvents"`
}

type FlawEventWithFlawNameDTO struct {
	flaw.FlawEventDTO
	FlawName string `json:"flawName"`
}

func OverviewToDto(o models.Overview) OverviewDTO {
	flawEvents := o.FlawEvents
	flawEventDTO := make([]FlawEventWithFlawNameDTO, len(o.FlawEvents))
	for i, flawEvent := range flawEvents {
		flawEventDTO[i] = flawEventToDto(flawEvent)
	}

	return OverviewDTO{
		TotalDependencies:           o.TotalDependencies,
		TotalCriticalDependencies:   o.TotalCriticalDependencies,
		AssetCombinedDependencies:   o.AssetCombinedDependencies,
		AssetRiskSummary:            o.AssetRiskSummary,
		AssetRiskDistribution:       o.AssetRiskDistribution,
		AssetRecentRisks:            o.AssetRecentRisks,
		AssetFlaws:                  o.AssetFlaws,
		AssetFlawsStateStatistics:   o.AssetFlawsStateStatistics,
		AssetHighestDamagedPackages: o.AssetHighestDamagedPackages,
		AssetComponents:             o.AssetComponents,
		FlawEvents:                  flawEventDTO,
	}
}

func flawEventToDto(flawEvent models.FlawEventWithFlawName) FlawEventWithFlawNameDTO {
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
