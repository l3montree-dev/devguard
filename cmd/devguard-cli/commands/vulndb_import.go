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
		Short: "Import vulnerability database from differential updates",
		Long:  "Imports the vulnerability database using differential CSV files. This applies incremental updates to the database rather than doing a full rebuild, making it faster for regular updates.",
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
				fx.Invoke(func(
					importService shared.VulnDBImportService,
				) error {
					return importService.ImportFromDiff(nil)
				}),
			)

			startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}

	return importCmd
}
