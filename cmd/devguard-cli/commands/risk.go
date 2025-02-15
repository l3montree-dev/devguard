package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

func NewRiskCommand() *cobra.Command {
	riskCmd := cobra.Command{
		Use:   "risk",
		Short: "Risk Assessment",
	}

	riskCmd.AddCommand(newCalculateCmd())
	return &riskCmd
}

func newCalculateCmd() *cobra.Command {
	calculateCmd := cobra.Command{
		Use:   "calculate",
		Short: "Will recalculate the risk assessments",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			flawRepository := repositories.NewFlawRepository(database)
			flawEventRepository := repositories.NewFlawEventRepository(database)
			cveRepository := repositories.NewCVERepository(database)
			assetRepository := repositories.NewAssetRepository(database)
			assetVersionRepository := repositories.NewAssetVersionRepository(database)
			flawService := flaw.NewService(flawRepository, flawEventRepository, assetRepository, cveRepository)
			statisticsRepository := repositories.NewStatisticsRepository(database)
			componentRepository := repositories.NewComponentRepository(database)
			projectRepository := repositories.NewProjectRepository(database)
			projectRiskHistoryRepository := repositories.NewProjectRiskHistoryRepository(database)

			statisticService := statistics.NewService(statisticsRepository, componentRepository, repositories.NewAssetRiskHistoryRepository(database), flawRepository, assetVersionRepository, projectRepository, projectRiskHistoryRepository)

			shouldCalculateHistory, err := cmd.Flags().GetBool("history")
			if err != nil {
				slog.Error("could not get flag", "err", err)
				return
			}

			if err := flawService.RecalculateAllRawRiskAssessments(); err != nil {
				slog.Error("could not recalculate risk assessments", "err", err)
				return
			}

			if shouldCalculateHistory {
				slog.Info("recalculating risk history")
				// fetch all assetVersions
				assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDB(nil)
				if err != nil {
					slog.Error("could not fetch assets", "err", err)
					return
				}

				for _, version := range assetVersions {
					slog.Info("recalculating risk history for asset", "assetVersionName", version.Name, "assetID", version.AssetId)
					if err := statisticService.UpdateAssetRiskAggregation(version.Name, version.AssetId, version.CreatedAt, time.Now(), true); err != nil {
						slog.Error("could not recalculate risk history", "err", err)
						return
					}
				}
			}
		},
	}

	calculateCmd.Flags().Bool("history", false, "if set, will recalculate the risk history for all assets")

	return &calculateCmd
}
