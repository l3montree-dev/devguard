package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/controllers"
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
		Long:  "Imports all changes since the last import from the OSV database",
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
					cveRepository shared.CveRepository,
					cweRepository shared.CweRepository,
					cveRelationshipRepository shared.CVERelationshipRepository,
					affectedCmpRepository shared.AffectedComponentRepository,
					configService shared.ConfigService,
					pool *pgxpool.Pool,
				) error {
					osvService := vulndb.NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository, configService, pool)
					return osvService.ImportRC(context.Background())
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

func newImportRCCommand() *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "importRC",
		Short: "Synchronize vulnerability data from upstream sources",
		Long: `Synchronizes vulnerability data from multiple upstream sources including:
  - CWE (Common Weakness Enumeration)
  - EPSS (Exploit Prediction Scoring System)
  - OSV (Open Source Vulnerabilities)
  - CISA KEV (Known Exploited Vulnerabilities)
  - ExploitDB and GitHub POCs
  - Malicious package databases

Use --databases flag to sync specific sources only.`,
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			migrateDB()
			app := fx.New(
				fx.NopLogger,
				database.Module,
				repositories.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				controllers.ControllerModule,
				services.ServiceModule,
				fx.Invoke(func(
					cveRepository shared.CveRepository,
					cveRelationshipRepository shared.CVERelationshipRepository,
					affectedCmpRepository shared.AffectedComponentRepository,
					configService shared.ConfigService,
					pool *pgxpool.Pool,
				) error {
					osvService := vulndb.NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository, configService, pool)
					startTime := time.Now()
					err := osvService.ImportRC(context.Background())
					if err != nil {
						return err
					}
					slog.Info("finished all syncs", "time elapsed", time.Since(startTime))
					return nil
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
	syncCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to sync. Possible values are: exploitdb, github-poc, cwe, epss, cisa-kev, osv, malicious-packages")

	return &syncCmd
}
