package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func newCleanupCommand() *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove orphaned database tables from failed imports",
		Long:  "Cleans up orphaned vulnerability database tables that are older than 24 hours. These tables are typically left behind from failed import operations and can consume significant disk space.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint

			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				vulndb.Module,
				repositories.Module,
				fx.Invoke(func(
					importService shared.VulnDBImportService,
				) error {
					if err := importService.CleanupOrphanedTables(); err != nil {
						return err
					}
					slog.Info("successfully cleaned up orphaned tables older than 24 hours")
					return nil
				}),
			)

			startCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}

	return cleanupCmd
}
