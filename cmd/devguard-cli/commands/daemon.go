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
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func markMirrored(configService services.ConfigService, key string) error {
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
			db, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return err
			}

			broker, err := database.BrokerFactory()
			if err != nil {
				slog.Error("failed to create broker", "err", err)
				panic(err)
			}

			daemons, _ := cmd.Flags().GetStringArray("daemons")

			return triggerDaemon(db, broker, daemons)
		},
	}

	trigger.Flags().StringArrayP("daemons", "d", []string{"vulndb", "fixedVersions", "risk", "tickets", "statistics", "deleteOldAssetVersions"}, "List of daemons to trigger")

	return trigger
}

func triggerDaemon(db shared.DB, broker database.Broker, selectedDaemons []string) error {
	// Create a minimal FX app to resolve all dependencies
	app := fx.New(
		// Provide the already-created db and broker
		fx.Supply(db),
		fx.Provide(database.BrokerFactory),
		// Include all the standard modules
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		controllers.ControllerModule,
		integrations.Module,

		// Invoke the daemon trigger function with all dependencies
		fx.Invoke(func(
			configService services.ConfigService,
			assetVersionRepository shared.AssetVersionRepository,
			assetRepository shared.AssetRepository,
			dependencyVulnRepository shared.DependencyVulnRepository,
			componentProjectRepository shared.ComponentProjectRepository,
			componentService shared.ComponentService,
			vulnEventRepository shared.VulnEventRepository,
			cveRepository shared.CveRepository,
			cweRepository shared.CweRepository,
			exploitsRepository shared.ExploitRepository,
			affectedComponentsRepository shared.AffectedComponentRepository,
			statisticsService shared.StatisticsService,
			artifactRepository shared.ArtifactRepository,
			dependencyVulnService shared.DependencyVulnService,
			integrationAggregate shared.IntegrationAggregate,
			scanController *controllers.ScanController,
			assetVersionService shared.AssetVersionService,
			projectRepository shared.ProjectRepository,
			orgRepository shared.OrganizationRepository,
			artifactService shared.ArtifactService,
			componentRepository shared.ComponentRepository,
		) {
			slog.Info("starting background jobs", "time", time.Now())
			var start time.Time

			if emptyOrContains(selectedDaemons, "deleteOldAssetVersions") {
				start = time.Now()
				err := daemons.DeleteOldAssetVersions(assetVersionRepository, vulnEventRepository)
				if err != nil {
					slog.Error("could not delete old asset versions", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.deleteOldAssetVersions"); err != nil {
					slog.Error("could not mark assetVersionsDelete as mirrored", "err", err)
					return
				}
				slog.Info("old asset versions deleted", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "openSourceInsights") {
				start = time.Now()
				err := daemons.UpdateOpenSourceInsightInformation(componentProjectRepository, componentService)
				if err != nil {
					slog.Error("could not update deps dev information", "err", err)
					return
				}
				slog.Info("deps dev information updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "scan") {
				start = time.Now()
				err := daemons.ScanArtifacts(db, scanController, assetVersionService, assetVersionRepository, assetRepository, projectRepository, orgRepository, artifactService, componentRepository)
				if err != nil {
					slog.Error("could not scan asset versions", "err", err)
					return
				}
				slog.Info("asset version scanned successfully", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "vulndb") {
				start = time.Now()
				if err := daemons.UpdateVulnDB(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService); err != nil {
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
				if err := daemons.UpdateFixedVersions(db, dependencyVulnRepository); err != nil {
					slog.Error("could not update component properties", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.componentProperties"); err != nil {
					slog.Error("could not mark vulndb.componentProperties as mirrored", "err", err)
				}
				slog.Info("component properties updated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "risk") {
				start = time.Now()
				if err := daemons.RecalculateRisk(dependencyVulnService); err != nil {
					slog.Error("could not recalculate risk", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.risk"); err != nil {
					slog.Error("could not mark vulndb.risk as mirrored", "err", err)
				}
				slog.Info("risk recalculated", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "tickets") {
				start = time.Now()
				if err := daemons.SyncTickets(db, integrationAggregate, dependencyVulnService, assetVersionRepository, assetRepository, projectRepository, orgRepository, dependencyVulnRepository); err != nil {
					slog.Error("could not sync tickets", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.tickets"); err != nil {
					slog.Error("could not mark vulndb.tickets as mirrored", "err", err)
				}
				slog.Info("tickets synced", "duration", time.Since(start))
			}

			if emptyOrContains(selectedDaemons, "statistics") {
				start = time.Now()
				if err := daemons.UpdateStatistics(statisticsService, assetVersionRepository, artifactRepository); err != nil {
					slog.Error("could not update statistics", "err", err)
					return
				}
				if err := markMirrored(configService, "vulndb.statistics"); err != nil {
					slog.Error("could not mark vulndb.statistics as mirrored", "err", err)
				}
				slog.Info("statistics updated", "duration", time.Since(start))
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
