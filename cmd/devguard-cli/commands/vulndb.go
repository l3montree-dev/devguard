package commands

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/router"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newSyncCommand())
	vulndbCmd.AddCommand(newImportCommand())
	vulndbCmd.AddCommand(newExportIncrementalCommand())
	vulndbCmd.AddCommand(newAliasMappingCommand())
	vulndbCmd.AddCommand(newCleanupCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	return slices.Contains(s, e)
}

func migrateDB(db shared.DB) {
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if err := database.RunMigrationsWithDB(db); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		var daemonRunner shared.DaemonRunner

		fx.New(
			// fx.NopLogger,
			fx.Supply(db),
			fx.Provide(database.BrokerFactory),
			fx.Provide(api.NewServer),
			repositories.Module,
			controllers.ControllerModule,
			services.ServiceModule,
			router.RouterModule,
			accesscontrol.AccessControlModule,
			integrations.Module,
			daemons.Module,

			// we need to invoke all routers to register their routes
			fx.Invoke(func(OrgRouter router.OrgRouter) {}),
			fx.Invoke(func(ProjectRouter router.ProjectRouter) {}),
			fx.Invoke(func(SessionRouter router.SessionRouter) {}),
			fx.Invoke(func(ArtifactRouter router.ArtifactRouter) {}),
			fx.Invoke(func(AssetRouter router.AssetRouter) {}),
			fx.Invoke(func(AssetVersionRouter router.AssetVersionRouter) {}),
			fx.Invoke(func(DependencyVulnRouter router.DependencyVulnRouter) {}),
			fx.Invoke(func(FirstPartyVulnRouter router.FirstPartyVulnRouter) {}),
			fx.Invoke(func(LicenseRiskRouter router.LicenseRiskRouter) {}),
			fx.Invoke(func(ShareRouter router.ShareRouter) {}),
			fx.Invoke(func(VulnDBRouter router.VulnDBRouter) {}),
			fx.Invoke(func(dependencyProxyRouter router.DependencyProxyRouter) {}),
			fx.Invoke(func(lc fx.Lifecycle, server api.Server) {
				lc.Append(fx.Hook{
					OnStart: func(ctx context.Context) error {
						go server.Start() // start in background
						return nil
					},
				})
			}),
			fx.Invoke(func(lc fx.Lifecycle, daemonRunner shared.DaemonRunner) {
				lc.Append(fx.Hook{
					OnStart: func(ctx context.Context) error {
						go daemonRunner.Start() // start in background
						return nil
					},
				})
			}),
			fx.Populate(&daemonRunner),
		)

	} else {
		slog.Info("automatic migrations disabled via DISABLE_AUTOMIGRATE=true")
	}
}

func newCleanupCommand() *cobra.Command {
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Cleans up orphaned vulndb tables older than specified hours",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := shared.LoadConfig(); err != nil {
				slog.Error("could not load config", "error", err)
				return
			}
			if err := vulndb.CleanupOrphanedTables(); err != nil {
				slog.Error("failed to cleanup orphaned tables", "error", err)
				return
			}

			slog.Info("successfully cleaned up orphaned tables older than 24 hours")
		},
	}

	return cleanupCmd
}

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Will import the vulnerability database",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			shared.LoadConfig() // nolint
			database, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "error", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)
			configService := services.NewConfigService(database)
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

			err = v.ImportFromDiff(nil)
			if err != nil {
				slog.Error("error when trying to import with diff files", "err", err)
			}
		},
	}

	return importCmd
}

func newSyncCommand() *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "sync",
		Short: "Will sync the vulnerability database",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			shared.LoadConfig() // nolint

			db, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(db)
			cweRepository := repositories.NewCWERepository(db)
			cveRelationshipRepository := repositories.NewCveRelationshipRepository(db)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(db)

			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository)

			// cvelistService := vulndb.NewCVEListService(cveRepository)
			debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			expoitDBService := vulndb.NewExploitDBService(repositories.NewExploitRepository(db))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(db))

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
				maliciousPackageRepository := repositories.NewMaliciousPackageRepository(db)
				maliciousPackageChecker, err := vulndb.NewMaliciousPackageChecker(maliciousPackageRepository)
				if err != nil {
					slog.Error("could not create malicious package checker", "err", err)
				} else if err := maliciousPackageChecker.DownloadAndProcessDB(); err != nil {
					slog.Error("could not sync malicious packages database", "err", err)
				}
				slog.Info("finished malicious packages database sync", "duration", time.Since(now))
			}
		},
	}
	syncCmd.Flags().String("after", "", "allows to only sync a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	syncCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")
	syncCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to sync. Possible values are: nvd, cvelist, exploitdb, github-poc, cwe, epss, osv, dsa, malicious-packages")

	return &syncCmd
}

func newExportIncrementalCommand() *cobra.Command {
	exportCmd := cobra.Command{
		Use:   "export",
		Short: "Will import the new vuln db after sync and export the diff of the old and new state of the vuln db",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// first import the new state
			shared.LoadConfig() // nolint
			os.RemoveAll("diffs-tmp/")
			shared.LoadConfig() // nolint
			database, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "error", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)
			configService := services.NewConfigService(database)
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)
			for _, arg := range args {
				slog.Info(arg)
			}

			// import the last vulndb version into some clean tables
			// we use the _diff suffix to identify those tables
			err = v.CreateTablesWithSuffix("_diff")
			if err != nil {
				slog.Error("error when trying to create tables with suffix", "err", err)
				return
			}
			err = v.ImportFromDiff(utils.Ptr("_diff"))
			if err != nil {
				slog.Error("error when trying to import with diff files", "err", err)
				return
			}
			err = vulndb.ExportDiffs("_diff")
			if err != nil {
				return
			}
		},
	}
	return &exportCmd
}
