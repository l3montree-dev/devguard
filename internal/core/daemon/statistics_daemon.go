package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func UpdateStatistics(db database.DB) error {
	assetRepository := repositories.NewAssetRepository(db)
	statisticsService := statistics.NewService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRiskHistoryRepository(db),
		repositories.NewFlawRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewProjectRiskHistoryRepository(db),
	)

	assets, err := assetRepository.GetAllAssetsFromDB()

	if err != nil {
		slog.Error("could not get assets from database", "err", err)
		return err
	}

	for _, asset := range assets {
		a := asset
		t := time.Now()
		slog.Info("recalculating risk history for asset", "asset", asset.ID)
		if err := statisticsService.UpdateAssetRiskAggregation(asset.ID, utils.OrDefault(asset.LastHistoryUpdate, asset.CreatedAt), t, true); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
			continue
		}
		// save the new LastHistoryUpdate timestamp
		a.LastHistoryUpdate = &t

		// save the asset
		if err := assetRepository.Save(nil, &a); err != nil {
			slog.Error("could not save asset", "err", err)
			continue
		}
		slog.Info("finished calculation of risk history for asset", "asset", a.ID, "duration", time.Since(t))
	}

	return nil
}
