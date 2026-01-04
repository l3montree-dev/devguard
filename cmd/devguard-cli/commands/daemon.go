package commands

import (
	"context"
	"log/slog"
	"time"

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

func triggerDaemon(selectedDaemons []string) error {
	// Create a minimal FX app to resolve all dependencies
	app := fx.New(
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
