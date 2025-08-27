package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func UpdateStatistics(db core.DB) error {
	start := time.Now()
	defer func() {
		monitoring.StatisticsUpdateDuration.Observe(time.Since(start).Minutes())
	}()

	assetVersionRepository := repositories.NewAssetVersionRepository(db)

	statisticsService := statistics.NewService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewArtifactRiskHistoryRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewAssetVersionRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewReleaseRepository(db),
	)

	assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDB(db)
	artifactService := artifact.NewService(
		repositories.NewArtifactRepository(db),
	)

	if err != nil {
		slog.Error("could not get assets from database", "err", err)
		return err
	}

	monitoring.AssetVersionsStatisticsAmount.Inc()
	for i, version := range assetVersions {
		a := version
		t := time.Now()
		slog.Info("recalculating risk history for asset", "assetVersionName", version.Name, "assetID", version.AssetID)
		artifacts, err := artifactService.GetArtifactNamesByAssetIDAndAssetVersionName(assetVersions[i].AssetID, assetVersions[i].Name)
		if err != nil {
			slog.Error("could not get artifacts for asset version", "assetVersionName", a.Name, "assetID", a.AssetID, "err", err)
			continue
		}
		for _, artifact := range artifacts {
			if err := statisticsService.UpdateArtifactRiskAggregation(&artifact, a.AssetID, utils.OrDefault(version.LastHistoryUpdate, version.CreatedAt), t, true); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
				continue
			}
			slog.Info("finished calculation of risk history for asset", "assetVersionName", a.Name, "assetID", a.AssetID, "duration", time.Since(t))

			err := assetVersionRepository.Save(db, &version)
			if err != nil {
				slog.Error("could not save asset", "err", err)
				// continue with the next asset - just log the error
				continue
			}
		}
		monitoring.AssetVersionsStatisticsSuccess.Inc()
	}

	monitoring.StatisticsUpdateDaemonAmount.Inc()
	return nil
}
