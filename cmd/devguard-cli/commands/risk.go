package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/DependencyVuln"
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

			vulnRepository := repositories.NewDependencyVulnerability(database)
			vulnEventRepository := repositories.NewVulnEventRepository(database)
			cveRepository := repositories.NewCVERepository(database)
			assetRepository := repositories.NewAssetRepository(database)
			vulnService := DependencyVuln.NewService(vulnRepository, vulnEventRepository, assetRepository, cveRepository)
			statisticsRepository := repositories.NewStatisticsRepository(database)
			componentRepository := repositories.NewComponentRepository(database)
			projectRepository := repositories.NewProjectRepository(database)
			projectRiskHistoryRepository := repositories.NewProjectRiskHistoryRepository(database)

			statisticService := statistics.NewService(statisticsRepository, componentRepository, repositories.NewAssetRiskHistoryRepository(database), vulnRepository, assetRepository, projectRepository, projectRiskHistoryRepository)

			shouldCalculateHistory, err := cmd.Flags().GetBool("history")
			if err != nil {
				slog.Error("could not get flag", "err", err)
				return
			}

			if err := vulnService.RecalculateAllRawRiskAssessments(); err != nil {
				slog.Error("could not recalculate risk assessments", "err", err)
				return
			}

			if shouldCalculateHistory {
				slog.Info("recalculating risk history")
				// fetch all assets
				assets, err := assetRepository.GetAllAssetsFromDB()
				if err != nil {
					slog.Error("could not fetch assets", "err", err)
					return
				}

				for _, asset := range assets {
					slog.Info("recalculating risk history for asset", "asset", asset.ID)
					if err := statisticService.UpdateAssetRiskAggregation(asset.ID, asset.CreatedAt, time.Now(), true); err != nil {
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
