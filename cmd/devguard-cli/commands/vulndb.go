package commands

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"

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
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Manage the vulnerability database",
		Long:  "Commands for managing, synchronizing, and maintaining the vulnerability database from multiple upstream sources including NVD, OSV, ExploitDB, and others.",
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

func migrateDB() {
	var err error

	pool := database.NewPgxConnPool(database.GetPoolConfigFromEnv())
	db := database.NewGormDB(pool)
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if err = database.RunMigrations(nil); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		var daemonRunner shared.DaemonRunner

		fx.New(
			fx.NopLogger,
			fx.Supply(db),
			fx.Provide(fx.Annotate(database.NewPostgreSQLBroker, fx.As(new(shared.PubSubBroker)))),
			fx.Provide(database.NewPostgreSQLBroker),
			fx.Provide(api.NewServer),
			repositories.Module,
			controllers.ControllerModule,
			services.ServiceModule,
			fx.Supply(pool),
			router.RouterModule,
			accesscontrol.AccessControlModule,
			integrations.Module,
			daemons.Module,
			vulndb.Module,
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
