package daemons

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func UpdateStatistics(
	statisticsService shared.StatisticsService,
	assetVersionRepository shared.AssetVersionRepository,
	artifactRepository shared.ArtifactRepository,
) error {
	start := time.Now()
	defer func() {
		monitoring.StatisticsUpdateDuration.Observe(time.Since(start).Minutes())
	}()

	monitoring.AssetVersionsStatisticsAmount.Inc()
	artifacts, err := artifactRepository.All()
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
