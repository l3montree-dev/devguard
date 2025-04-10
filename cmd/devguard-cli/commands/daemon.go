package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
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

			daemons, _ := cmd.Flags().GetStringArray("daemons")

			return triggerDaemon(database, daemons)
		},
	}

	trigger.Flags().StringArrayP("daemons", "d", []string{"vulndb", "componentProperties", "risk", "tickets", "statistics"}, "List of daemons to trigger")

	return trigger
}

func triggerDaemon(db core.DB, daemons []string) error {
	configService := config.NewService(db)

	// we only update the vulnerability database each 6 hours.
	// thus there is no need to recalculate the risk or anything earlier
	slog.Info("starting background jobs", "time", time.Now())
	var start time.Time = time.Now()
	// update deps dev
	err := daemon.UpdateDepsDevInformation(db)
	if err != nil {
		slog.Error("could not update deps dev information", "err", err)
		return nil
	}
	slog.Info("deps dev information updated", "duration", time.Since(start))

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
		if err := daemon.RecalculateRisk(db); err != nil {
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
		if err := daemon.SyncTickets(db); err != nil {
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
