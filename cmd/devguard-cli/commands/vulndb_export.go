package commands

import (
	"context"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func newExportIncrementalCommand() *cobra.Command {
	exportCmd := cobra.Command{
		Use:   "export",
		Short: "Export differential updates between database states",
		Long:  "Imports the latest vulnerability database state and exports the differences between the old and new states as CSV files. This is useful for creating incremental update packages that can be distributed to other instances.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			os.RemoveAll("diffs-tmp/")
			migrateDB()
			app := fx.New(
				fx.NopLogger,
				database.Module,
				vulndb.Module,
				services.ServiceModule,
				repositories.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				fx.Invoke(func(
					db shared.DB,
					importService shared.VulnDBImportService,
				) error {
					if err := importService.CreateTablesWithSuffix("_diff"); err != nil {
						return err
					}
					if err := importService.ImportFromDiff(utils.Ptr("_diff")); err != nil {
						return err
					}
					return importService.ExportDiffs("_diff")
				}),
			)

			startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}
	return &exportCmd
}
