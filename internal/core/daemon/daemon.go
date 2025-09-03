package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/leaderelection"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/pubsub"
	"gorm.io/gorm"
)

func getLastMirrorTime(configService config.Service, key string) (time.Time, error) {
	var lastMirror struct {
		Time time.Time `json:"time"`
	}

	err := configService.GetJSONConfig(key, &lastMirror)

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error("could not get last mirror time", "err", err, "key", key)
		return time.Time{}, err
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Info("no last mirror time found. Setting to 0", "key", key)
		return time.Time{}, nil
	}

	return lastMirror.Time, nil
}

func shouldMirror(configService config.Service, key string) bool {
	lastTime, err := getLastMirrorTime(configService, key)
	if err != nil {
		return false
	}

	return time.Since(lastTime) > 12*time.Hour
}

func markMirrored(configService config.Service, key string) error {
	return configService.SetJSONConfig(key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func runDaemons(db core.DB, broker pubsub.Broker, configService config.Service) error {
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

	daemonStart := time.Now()
	defer time.Sleep(5 * time.Minute) // wait for 5 minutes before checking again - always - even in case of error
	// we only update the vulnerability database each 6 hours.
	// thus there is no need to recalculate the risk or anything earlier
	slog.Info("starting background jobs", "time", time.Now())
	var start = time.Now()

	if shouldMirror(configService, "vulndb.deleteOldAssetVersions") {
		start = time.Now()
		// delete old asset versions
		err := DeleteOldAssetVersions(db)
		if err != nil {
			slog.Error("could not delete old asset versions", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.deleteOldAssetVersions"); err != nil {
			slog.Error("could not mark deleteOldAssetVersions as mirrored", "err", err)
		}
		slog.Info("old asset versions deleted", "duration", time.Since(start))
	}

	// update deps dev
	if shouldMirror(configService, "vulndb.opensourceinsights") {
		err := UpdateOpenSourceInsightInformation(db)
		if err != nil {
			slog.Error("could not update deps dev information", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.opensourceinsights"); err != nil {
			slog.Error("could not mark deps dev as mirrored", "err", err)
		}
		slog.Info("deps dev information updated", "duration", time.Since(start))
	}

	// first update the vulndb
	// this will give us the latest cves, cwes, exploits and affected components
	if shouldMirror(configService, "vulndb.vulndb") {
		start = time.Now()
		if err := UpdateVulnDB(db); err != nil {
			slog.Error("could not update vulndb", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.vulndb"); err != nil {
			slog.Error("could not mark vulndb.vulndb as mirrored", "err", err)
		}
		slog.Info("vulndb updated", "duration", time.Since(start))
	}

	if shouldMirror(configService, "vulndb.scan") {
		start = time.Now()
		// update the scan
		if err := ScanArtifacts(db, casbinRBACProvider); err != nil {
			slog.Error("could not update scan", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.scan"); err != nil {
			slog.Error("could not mark vulndb.scan as mirrored", "err", err)
		}
		slog.Info("scan updated", "duration", time.Since(start))
	}

	if shouldMirror(configService, "vulndb.autoReopen") {
		start = time.Now()
		// update the auto reopen
		if err := AutoReopenAcceptedVulnerabilities(db); err != nil {
			slog.Error("could not update auto reopen", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.autoReopen"); err != nil {
			slog.Error("could not mark vulndb.autoReopen as mirrored", "err", err)
		}
		slog.Info("auto reopen updated", "duration", time.Since(start))
	}

	// after we have a fresh vulndb we can update the dependencyVulns.
	// we save data inside the dependency_vulns table: ComponentDepth and ComponentFixedVersion
	// those need to be updated before recalculating the risk
	if shouldMirror(configService, "vulndb.fixedVersions") {
		start = time.Now()
		if err := UpdateFixedVersions(db); err != nil {
			slog.Error("could not update fixed versions", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.fixedVersions"); err != nil {
			slog.Error("could not mark vulndb.fixedVersions as mirrored", "err", err)
		}
		slog.Info("fixedVersions updated", "duration", time.Since(start))
	}

	if shouldMirror(configService, "vulndb.risk") {
		start = time.Now()
		// finally, recalculate the risk.
		if err := RecalculateRisk(db, thirdPartyIntegrationAggregate); err != nil {
			slog.Error("could not recalculate risk", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.risk"); err != nil {
			slog.Error("could not mark vulndb.risk as mirrored", "err", err)
		}
		slog.Info("risk recalculated", "duration", time.Since(start))
	}

	if shouldMirror(configService, "vulndb.tickets") {
		start = time.Now()
		// sync tickets
		if err := SyncTickets(db, thirdPartyIntegrationAggregate); err != nil {
			slog.Error("could not sync tickets", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.tickets"); err != nil {
			slog.Error("could not mark vulndb.tickets as mirrored", "err", err)
		}
		slog.Info("tickets synced", "duration", time.Since(start))
	}

	if shouldMirror(configService, "vulndb.statistics") {
		start = time.Now()
		// as a last step - update the statistics
		if err := UpdateStatistics(db); err != nil {
			slog.Error("could not update statistics", "err", err)
			return nil
		}
		if err := markMirrored(configService, "vulndb.statistics"); err != nil {
			slog.Error("could not mark vulndb.statistics as mirrored", "err", err)
		}
		slog.Info("statistics updated", "duration", time.Since(start))
	}

	slog.Info("background jobs finished", "duration", time.Since(daemonStart))

	return nil
}

func Start(db core.DB, broker pubsub.Broker) {
	configService := config.NewService(db)
	leaderElector := leaderelection.NewDatabaseLeaderElector(configService)

	go func() {
		// check if the vulndb is empty
		if err := db.Exec("SELECT 1 FROM cves LIMIT 1").Scan(new(int)).Error; err != nil {
			slog.Warn("vulndb is empty. skipping leader election and running daemons directly", "err", err)
			if err := runDaemons(db, broker, configService); err != nil {
				slog.Error("could not run daemons", "err", err)
			}
			return
		}
		leaderElector.IfLeader(context.Background(), func() error {
			return runDaemons(db, broker, configService)
		})
	}()

}
