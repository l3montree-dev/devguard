package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/pubsub"
	"github.com/spf13/cobra"
)

func markMirrored(configService config.Service, key string) error {
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
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return err
			}

			broker, err := pubsub.BrokerFactory()
			if err != nil {
				slog.Error("failed to create broker", "err", err)
				panic(err)
			}

			daemons, _ := cmd.Flags().GetStringArray("daemons")

			return triggerDaemon(database, broker, daemons)
		},
	}

	trigger.Flags().StringArrayP("daemons", "d", []string{"vulndb", "componentProperties", "risk", "tickets", "statistics", "deleteOldAssetVersions"}, "List of daemons to trigger")

	return trigger
}

func triggerDaemon(db core.DB, broker pubsub.Broker, daemons []string) error {
	configService := config.NewService(db)
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db, broker)
	if err != nil {
		panic(err)
	}
	githubIntegration := githubint.NewGithubIntegration(db)
	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)
	gitlabIntegration := gitlabint.NewGitlabIntegration(db, gitlabOauth2Integrations, casbinRBACProvider, gitlabClientFactory)

	thirdPartyIntegrationAggregate := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

	// we only update the vulnerability database each 6 hours.
	// thus there is no need to recalculate the risk or anything earlier
	slog.Info("starting background jobs", "time", time.Now())
	var start time.Time
	if emptyOrContains(daemons, "deleteOldAssetVersions") {
		start = time.Now()
		// delete old asset versions
		err := daemon.DeleteOldAssetVersions(db)
		if err != nil {
			slog.Error("could not delete old asset versions", "err", err)
			return nil
		}

		if err := markMirrored(configService, "vulndb.deleteOldAssetVersions"); err != nil {
			slog.Error("could not mark assetVersionsDelete as mirrored", "err", err)
			return nil
		}

		slog.Info("old asset versions deleted", "duration", time.Since(start))
	}

	if emptyOrContains(daemons, "depsDev") {
		start = time.Now()
		// update deps dev
		err := daemon.UpdateDepsDevInformation(db)
		if err != nil {
			slog.Error("could not update deps dev information", "err", err)
			return nil
		}
		slog.Info("deps dev information updated", "duration", time.Since(start))
	}

	if emptyOrContains(daemons, "scan") {
		start = time.Now()
		// update scan
		err := daemon.ScanAssetVersions(db, casbinRBACProvider)
		if err != nil {
			slog.Error("could not scan asset versions", "err", err)
			return nil
		}
		slog.Info("asset version scanned successfully", "duration", time.Since(start))
	}
	// first update the vulndb
	// this will give us the latest cves, cwes, exploits and affected components
	if emptyOrContains(daemons, "vulndb") {
		start = time.Now()
		if err := daemon.UpdateVulnDB(db); err != nil {
			slog.Error("could not update vulndb", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.vulndb"); err != nil {
			slog.Error("could not mark vulndb.vulndb as mirrored", "err", err)
		}
		slog.Info("vulndb updated", "duration", time.Since(start))
	}

	// after we have a fresh vulndb we can update the dependencyVulns.
	// we save data inside the dependency_vulns table: ComponentDepth and ComponentFixedVersion
	// those need to be updated before recalculating the risk
	if emptyOrContains(daemons, "componentProperties") {
		start = time.Now()
		if err := daemon.UpdateComponentProperties(db); err != nil {
			slog.Error("could not update component properties", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.componentProperties"); err != nil {
			slog.Error("could not mark vulndb.componentProperties as mirrored", "err", err)
		}
		slog.Info("component properties updated", "duration", time.Since(start))
	}

	if emptyOrContains(daemons, "risk") {
		start = time.Now()
		// finally, recalculate the risk.
		if err := daemon.RecalculateRisk(db, thirdPartyIntegrationAggregate); err != nil {
			slog.Error("could not recalculate risk", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.risk"); err != nil {
			slog.Error("could not mark vulndb.risk as mirrored", "err", err)
		}
		slog.Info("risk recalculated", "duration", time.Since(start))
	}

	if emptyOrContains(daemons, "tickets") {
		start = time.Now()
		if err := daemon.SyncTickets(db, thirdPartyIntegrationAggregate); err != nil {
			slog.Error("could not sync tickets", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.tickets"); err != nil {
			slog.Error("could not mark vulndb.tickets as mirrored", "err", err)
		}
		slog.Info("tickets synced", "duration", time.Since(start))
	}

	if emptyOrContains(daemons, "statistics") {
		start = time.Now()
		// as a last step - update the statistics
		if err := daemon.UpdateStatistics(db); err != nil {
			slog.Error("could not update statistics", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.statistics"); err != nil {
			slog.Error("could not mark vulndb.statistics as mirrored", "err", err)
		}
		slog.Info("statistics updated", "duration", time.Since(start))
	}

	return nil
}
