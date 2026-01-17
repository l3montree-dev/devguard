package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func markMirrored(configService shared.ConfigService, key string) error {
	return configService.SetJSONConfig(key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func NewDaemonCommand() *cobra.Command {
	daemon := cobra.Command{
		Use:   "daemon",
		Short: "daemon",
	}

	daemon.AddCommand(newTriggerCommand())
	daemon.AddCommand(newRunPipelineForAssetCommand())
	return &daemon
}

func newTriggerCommand() *cobra.Command {
	trigger := &cobra.Command{
		Use:   "trigger",
		Short: "Will trigger the background jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			daemons, _ := cmd.Flags().GetStringArray("daemons")

			return triggerDaemon(daemons)
		},
	}

	trigger.Flags().StringArrayP("daemons", "d", []string{"vulndb", "fixedVersions", "risk", "tickets", "statistics", "deleteOldAssetVersions"}, "List of daemons to trigger")

	return trigger
}

func newRunPipelineForAssetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runPipeline [asset-id]",
		Short: "Run the asset pipeline for a single asset",
		Long: `Runs the full asset pipeline (scan, risk recalculation, ticket sync, etc.) for a single asset.
Useful for debugging. You can further scope with --asset-version and --vuln-id flags.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			assetID := args[0]
			assetVersion, _ := cmd.Flags().GetString("assetVersionSlug")
			return runPipelineForAsset(assetID, assetVersion)
		},
	}
	cmd.Flags().StringP("assetVersionSlug", "v", "", "Scope to a specific asset version name")

	return cmd
}

func runPipelineForAsset(assetIDStr, assetVersionSlug string) error {
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		slog.Error("invalid asset ID", "assetID", assetIDStr, "err", err)
		return err
	}

	var daemonRunner shared.DaemonRunner
	var dependencyVulnRepository shared.DependencyVulnRepository
	var dependencyVulnService shared.DependencyVulnService
	var assetRepository shared.AssetRepository
	var assetVersionRepository shared.AssetVersionRepository

	app := fx.New(
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.NopLogger,
		database.Module,
		fx.Provide(database.NewPostgreSQLBroker),
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		controllers.ControllerModule,
		integrations.Module,
		vulndb.Module,
		daemons.Module,
		fx.Populate(&daemonRunner, &dependencyVulnRepository, &dependencyVulnService, &assetRepository, &assetVersionRepository),
	)

	if err := app.Err(); err != nil {
		return err
	}
	runner := daemonRunner.(*daemons.DaemonRunner)

	// Otherwise run full pipeline for asset
	slog.Info("running full asset pipeline", "assetID", assetID)
	runner.SetDebugOptions(daemons.DebugOptions{
		LimitToAssetVersionSlug: assetVersionSlug,
	})

	if err := runner.RunDaemonPipelineForAsset(assetID); err != nil {
		slog.Error("pipeline failed", "assetID", assetID, "err", err)
		return err
	}

	slog.Info("successfully ran asset pipeline", "assetID", assetID)
	return nil
}

func triggerDaemon(selectedDaemons []string) error {
	// Create a minimal FX app to resolve all dependencies
	app := fx.New(
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.NopLogger,
		database.Module,
		fx.Provide(database.NewPostgreSQLBroker),
		// Include all the standard modules
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		controllers.ControllerModule,
		integrations.Module,
		vulndb.Module,
		daemons.Module,

		// Invoke the daemon trigger function with all dependencies
		fx.Invoke(func(
			runner shared.DaemonRunner,
			configService shared.ConfigService,
		) {
			slog.Info("starting background jobs", "time", time.Now())
			var start time.Time

			if emptyOrContains(selectedDaemons, "openSourceInsights") {
				start = time.Now()
				err := runner.UpdateOpenSourceInsightInformation()
				if err != nil {
					slog.Error("could not update deps dev information", "err", err)
					return
				}
				slog.Info("deps dev information updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "vulndb") {
				start = time.Now()
				if err := runner.UpdateVulnDB(); err != nil {
					slog.Error("could not update vulndb", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.vulndb"); err != nil {
					slog.Error("could not mark vulndb.vulndb as mirrored", "err", err)
				}
				slog.Info("vulndb updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "fixedVersions") {
				start = time.Now()
				if err := runner.UpdateFixedVersions(); err != nil {
					slog.Error("could not update component properties", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.componentProperties"); err != nil {
					slog.Error("could not mark vulndb.componentProperties as mirrored", "err", err)
				}
				slog.Info("component properties updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "assetPipeline") {
				start = time.Now()
				runner.RunAssetPipeline(true)
				slog.Info("asset pipeline run completed", "duration", time.Since(start))
			}
		}),
	)

	// Start and stop the app to run the daemons
	startCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		return err
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return app.Stop(stopCtx)
}
