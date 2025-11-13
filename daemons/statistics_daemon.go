package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
)

func UpdateStatistics(db shared.DB) error {
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

	artifactRepo := repositories.NewArtifactRepository(db)

	monitoring.AssetVersionsStatisticsAmount.Inc()
	artifacts, err := artifactRepo.All()
	if err != nil {
		slog.Error("could not get all artifacts", "err", err)
		return err
	}
	errgroup := utils.ErrGroup[any](10)
	for _, artifact := range artifacts {
		errgroup.Go(func() (any, error) {
			if err := statisticsService.UpdateArtifactRiskAggregation(&artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
				return nil, nil
			}

			err := assetVersionRepository.GetDB(nil).Save(&artifact).Error
			if err != nil {
				slog.Error("could not save asset", "err", err)
				// continue with the next asset - just log the error
				return nil, nil
			}
			slog.Info("updated statistics for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", artifact.AssetVersionName, "assetID", artifact.AssetID)
			monitoring.AssetVersionsStatisticsSuccess.Inc()
			return nil, nil
		})
	}
	monitoring.StatisticsUpdateDaemonAmount.Inc()
	return nil
}
