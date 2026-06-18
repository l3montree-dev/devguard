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
	"github.com/l3montree-dev/devguard/fixedversion"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func markMirrored(configService shared.ConfigService, key string) error {
	return configService.SetJSONConfig(context.Background(), key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func NewDaemonCommand() *cobra.Command {
	daemon := cobra.Command{
		Use:   "daemon",
		Short: "Manage and trigger background daemon jobs",
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
Useful for debugging. You can further scope with --assetVersionSlug flag.

Use --dryRun to run in safe read-only mode: the database connection is opened
with default_transaction_read_only=on and all ticket mutations (open, close,
update) are replaced by log lines showing what would have happened.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			assetID := args[0]
			assetVersion, _ := cmd.Flags().GetString("assetVersionSlug")
			dryRun, _ := cmd.Flags().GetBool("dryRun")
			stages, _ := cmd.Flags().GetStringArray("stage")
			return runPipelineForAsset(assetID, assetVersion, dryRun, stages)
		},
	}
	cmd.Flags().StringP("assetVersionSlug", "v", "", "Scope to a specific asset version name")
	cmd.Flags().Bool("dryRun", true, "Read-only mode: log ticket operations instead of executing them, never write to the database (default: true, use --dryRun=false to apply changes)")
	cmd.Flags().StringArray("stage", []string{}, "Run only the specified pipeline stage(s), can be repeated (e.g. --stage SyncTickets --stage CollectStats). Valid values: SyncTickets, ResolveDifferencesInTicketState, ScanAsset, SyncUpstream, CollectStats, RecalculateRiskForVulnerabilities, AutoReopenTickets, DeleteOldAssetVersions, ResolveFixedVersions")

	return cmd
}

func runPipelineForAsset(assetIDStr, assetVersionSlug string, dryRun bool, stages []string) error {
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

	poolCfg := database.GetPoolConfigFromEnv()
	if dryRun {
		slog.Warn("[DRY-RUN] running in dry-run mode — all database writes will be rolled back, no external system mutations will occur")
	}

	fxOpts := []fx.Option{
		fx.Supply(poolCfg),
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
		fixedversion.Module,
		fx.Populate(&daemonRunner, &dependencyVulnRepository, &dependencyVulnService, &assetRepository, &assetVersionRepository),
	}

	if dryRun {
		fxOpts = append(fxOpts, fx.Decorate(func(real shared.IntegrationAggregate) shared.IntegrationAggregate {
			return integrations.NewDryRunIntegration(real)
		}))
	}

	app := fx.New(fxOpts...)

	if err := app.Err(); err != nil {
		return err
	}
	runner := daemonRunner.(*daemons.DaemonRunner)

	slog.Info("running asset pipeline", "assetID", assetID, "dryRun", dryRun, "stages", stages, "assetVersionSlug", assetVersionSlug)
	runner.SetDebugOptions(daemons.DebugOptions{
		LimitToAssetVersionSlug: assetVersionSlug,
		LimitToStages:           stages,
		DryRun:                  dryRun,
	})

	if err := runner.RunDaemonPipelineForAsset(context.Background(), assetID); err != nil {
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
		fixedversion.Module,

		// Invoke the daemon trigger function with all dependencies
		fx.Invoke(func(
			runner shared.DaemonRunner,
			configService shared.ConfigService,
		) {
			slog.Info("starting background jobs", "time", time.Now())
			var start time.Time

			if emptyOrContains(selectedDaemons, "openSourceInsights") {
				start = time.Now()
				err := runner.UpdateOpenSourceInsightInformation(context.Background())
				if err != nil {
					slog.Error("could not update deps dev information", "err", err)
					return
				}
				slog.Info("deps dev information updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "vulndb") {
				start = time.Now()
				if err := runner.UpdateVulnDB(context.Background()); err != nil {
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
				if err := runner.UpdateFixedVersions(context.Background()); err != nil {
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
				runner.RunAssetPipeline(context.Background(), true)
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
