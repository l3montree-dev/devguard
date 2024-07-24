package commands

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
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
			flawService := flaw.NewService(flawRepository, flawEventRepository, assetRepository, cveRepository)

			if err := flawService.RecalculateAllRawRiskAssessments(); err != nil {
				slog.Error("could not recalculate risk assessments", "err", err)
				return
			}
		},
	}

	return &calculateCmd
}
