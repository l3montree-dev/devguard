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
	assetVersionRepository := repositories.NewAssetVersionRepository(db)

	statisticsService := statistics.NewService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRiskHistoryRepository(db),
		repositories.NewFlawRepository(db),
		repositories.NewAssetVersionRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewProjectRiskHistoryRepository(db),
	)

	assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDB(db)

	if err != nil {
		slog.Error("could not get assets from database", "err", err)
		return err
	}

	for _, version := range assetVersions {
		a := version
		t := time.Now()
		slog.Info("recalculating risk history for asset", "assetVersionName", version.Name, "assetID", version.AssetID)
		if err := statisticsService.UpdateAssetRiskAggregation(version, a.AssetID, utils.OrDefault(version.LastHistoryUpdate, version.CreatedAt), t, true); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
			continue
		}
		slog.Info("finished calculation of risk history for asset", "assetVersionName", a.Name, "assetID", a.AssetID, "duration", time.Since(t))
	}

	return nil
}
