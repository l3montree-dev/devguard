package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func newSyncCommand() *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "sync",
		Short: "Synchronize vulnerability data from upstream sources",
		Long: `Synchronizes vulnerability data from multiple upstream sources including:
  - CWE (Common Weakness Enumeration)
  - EPSS (Exploit Prediction Scoring System)
  - OSV (Open Source Vulnerabilities)
  - CISA KEV (Known Exploited Vulnerabilities)
  - ExploitDB and GitHub POCs
  - Debian Security Tracker
  - Malicious package databases

Use --databases flag to sync specific sources only.`,
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

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
					cweRepository shared.CweRepository,
					cveRelationshipRepository shared.CVERelationshipRepository,
					affectedCmpRepository shared.AffectedComponentRepository,
					exploitRepository shared.ExploitRepository,
					maliciousPackageChecker shared.MaliciousPackageChecker,
				) error {

					mitreService := vulndb.NewMitreService(cweRepository)
					epssService := vulndb.NewEPSSService(cveRepository, cveRelationshipRepository)
					cisaKEVService := vulndb.NewCISAKEVService(cveRepository, cveRelationshipRepository)
					osvService := vulndb.NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository)
					debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)
					expoitDBService := vulndb.NewExploitDBService(exploitRepository)
					githubExploitDBService := vulndb.NewGithubExploitDBService(exploitRepository)

					if emptyOrContains(databasesToSync, "cwe") {
						now := time.Now()
						slog.Info("starting cwe database sync")
						if err := mitreService.Mirror(); err != nil {
							slog.Error("could not mirror cwe database", "err", err)
						}
						slog.Info("finished cwe database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "osv") {
						slog.Info("starting osv database sync")
						now := time.Now()
						if err := osvService.Mirror(); err != nil {
							slog.Error("could not sync osv database", "err", err)
						}
						slog.Info("finished osv database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "epss") {
						slog.Info("starting epss database sync")
						now := time.Now()

						if err := epssService.Mirror(); err != nil {
							slog.Error("could not sync epss database", "err", err)
						}
						slog.Info("finished epss database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "cisa-kev") {
						slog.Info("starting cisa-kev database sync")
						now := time.Now()

						if err := cisaKEVService.Mirror(); err != nil {
							slog.Error("could not sync cisa-kev database", "err", err)
						}
						slog.Info("finished cisa-kev database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "exploitdb") {
						slog.Info("starting exploitdb database sync")
						now := time.Now()
						if err := expoitDBService.Mirror(); err != nil {
							slog.Error("could not sync exploitdb database", "err", err)
						}
						slog.Info("finished exploitdb database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "github-poc") {
						slog.Info("starting github-poc database sync")
						now := time.Now()
						if err := githubExploitDBService.Mirror(); err != nil {
							slog.Error("could not sync github-poc database", "err", err)
						}
						slog.Info("finished github-poc database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "dsa") {
						slog.Info("starting dsa database sync")
						now := time.Now()
						if err := debianSecurityTracker.Mirror(); err != nil {
							slog.Error("could not sync dsa database", "err", err)
						}
						slog.Info("finished dsa database sync", "duration", time.Since(now))
					}

					if emptyOrContains(databasesToSync, "malicious-packages") {
						slog.Info("starting malicious packages database sync")
						now := time.Now()

						if err := maliciousPackageChecker.DownloadAndProcessDB(); err != nil {
							slog.Error("could not sync malicious packages database", "err", err)
						}
						slog.Info("finished malicious packages database sync", "duration", time.Since(now))
					}
					return nil
				}),
			)

			startCtx, cancel := context.WithTimeout(context.Background(), 120*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}
	syncCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to sync. Possible values are: exploitdb, github-poc, cwe, epss, cisa-kev, osv, dsa, malicious-packages")

	return &syncCmd
}
