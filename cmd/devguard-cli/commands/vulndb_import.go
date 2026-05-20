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
	var batchSize int
	var bulk bool
	var limitedToTables []string
	var debug bool
	var localArchive bool

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import the latest state of the vulnerability database",
		Long:  "Pulls the pre-built vulndb artifact from the OCI registry and applies all changes to the local database",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			migrateDB()
			opts := shared.ImportOptions{
				BatchSize:       batchSize,
				Bulk:            bulk,
				LimitedToTables: limitedToTables,
				Debug:           debug,
				LocalArchive:    localArchive,
			}
			app := fx.New(
				fx.NopLogger,
				database.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				repositories.Module,
				services.ServiceModule,
				vulndb.Module,
				fx.Invoke(func(svc shared.VulnDBService) error {
					return svc.ImportRC(context.Background(), opts)
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

	importCmd.Flags().IntVar(&batchSize, "batchSize", 5000, "Number of OSV entries per batch (default 5000)")
	importCmd.Flags().BoolVar(&bulk, "bulk", false, "Load all gob data into RAM before writing (faster but uses ~2-3 GB memory)")
	importCmd.Flags().StringSliceVar(&limitedToTables, "limitedToTables", []string{}, "Comma-separated list of tables to limit the import to (e.g. --limitedToTables=cves,exploits,malicious_packages)")
	importCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	importCmd.Flags().BoolVar(&localArchive, "local-archive", false, "Read from vulndb.tar.zst in the current directory instead of pulling from OCI")

	return importCmd
}

func newExportCommand() *cobra.Command {
	var diffToPrevious bool
	var localArchive bool

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
					if diffToPrevious {
						return svc.ExportRCWithDiff(context.Background(), localArchive)
					}
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

	exportCmd.Flags().BoolVar(&diffToPrevious, "diff-to-previous", false,
		"Compute a QuickDiff against the previous export so importers on the last version can skip staging entirely")
	exportCmd.Flags().BoolVar(&localArchive, "local-archive", false,
		"Use vulndb.tar.zst in the current directory for the baseline import instead of pulling from OCI")

	return exportCmd
}
