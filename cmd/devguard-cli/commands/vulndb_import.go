package commands

import (
	"context"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import the latest state of the vulnerability database",
		Long:  "Pulls the pre-built vulndb artifact from the OCI registry and applies all changes to the local database",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			migrateDB()
			app := fx.New(
				fx.NopLogger,
				database.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				repositories.Module,
				services.ServiceModule,
				vulndb.Module,
				fx.Invoke(func(svc shared.VulnDBService) error {
					return svc.ImportRC(context.Background())
				}),
			)

			ctx := context.Background()
			startCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}

	return importCmd
}

func newExportCommand() *cobra.Command {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export the vulnerability database to an OCI artifact",
		Long:  "Fetches all vulnerability data sources, writes gob files, and produces an integrity manifest",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			migrateDB()
			app := fx.New(
				fx.NopLogger,
				database.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				repositories.Module,
				services.ServiceModule,
				vulndb.Module,
				fx.Invoke(func(svc shared.VulnDBService) error {
					return svc.ExportRC(context.Background())
				}),
			)

			ctx := context.Background()
			startCtx, cancel := context.WithTimeout(ctx, 120*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}

	return exportCmd
}
