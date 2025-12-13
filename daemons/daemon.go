package daemons

import (
	"context"

	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func getLastMirrorTime(configService shared.ConfigService, key string) (time.Time, error) {
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

func shouldMirror(configService shared.ConfigService, key string) bool {
	lastTime, err := getLastMirrorTime(configService, key)
	if err != nil {
		return false
	}

	return time.Since(lastTime) > 12*time.Hour
}

func markMirrored(configService shared.ConfigService, key string) error {
	return configService.SetJSONConfig(key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func (runner DaemonRunner) runDaemons() error {

	daemonStart := time.Now()
	defer time.Sleep(5 * time.Minute) // wait for 5 minutes before checking again - always - even in case of error
	// we only update the vulnerability database each 6 hours.
	// thus there is no need to recalculate the risk or anything earlier
	slog.Info("starting background jobs", "time", time.Now())
	var start = time.Now()

	if shouldMirror(runner.configService, "vulndb.deleteOldAssetVersions") {
		start = time.Now()
		// delete old asset versions
		err := runner.DeleteOldAssetVersions()
		if err != nil {
			slog.Error("could not delete old asset versions", "err", err)
			return nil
		}
		if err := markMirrored(runner.configService, "vulndb.deleteOldAssetVersions"); err != nil {
			slog.Error("could not mark deleteOldAssetVersions as mirrored", "err", err)
		}
		slog.Info("old asset versions deleted", "duration", time.Since(start))
	}

	// update deps dev
	if shouldMirror(runner.configService, "vulndb.opensourceinsights") {
		err := runner.UpdateOpenSourceInsightInformation()
		if err != nil {
			slog.Error("could not update deps dev information", "err", err)
			return nil
		}
		if err := markMirrored(runner.configService, "vulndb.opensourceinsights"); err != nil {
			slog.Error("could not mark deps dev as mirrored", "err", err)
		}
		slog.Info("deps dev information updated", "duration", time.Since(start))
	}

	// first update the vulndb
	// this will give us the latest cves, cwes, exploits and affected components
	if shouldMirror(runner.configService, "vulndb.vulndb") {
		start = time.Now()
		if err := runner.UpdateVulnDB(); err != nil {
			monitoring.Alert("failed to update vulndb", err)
			// We do not return right here! Even if the vulndb update fails, we mark it as mirrored to avoid getting stuck in an endless loop
			// of backup tables.
		}
		if err := markMirrored(runner.configService, "vulndb.vulndb"); err != nil {
			slog.Error("could not mark vulndb.vulndb as mirrored", "err", err)
		}
		slog.Info("vulndb updated", "duration", time.Since(start))
	}

	// after we have a fresh vulndb we can update the dependencyVulns.
	// we save data inside the dependency_vulns table: ComponentDepth and ComponentFixedVersion
	// those need to be updated before recalculating the risk
	if shouldMirror(runner.configService, "vulndb.fixedVersions") {
		start = time.Now()
		if err := runner.UpdateFixedVersions(); err != nil {
			slog.Error("could not update fixed versions", "err", err)
			return nil
		}
		if err := markMirrored(runner.configService, "vulndb.fixedVersions"); err != nil {
			slog.Error("could not mark vulndb.fixedVersions as mirrored", "err", err)
		}
		slog.Info("fixedVersions updated", "duration", time.Since(start))
	}

	slog.Info("background jobs finished", "duration", time.Since(daemonStart))

	return nil
}

func (runner DaemonRunner) startBackgroundDaemons() {
	go func() {
		// check if the vulndb is empty
		if err := runner.db.Raw("SELECT 1 as count FROM cves LIMIT 1;").Scan(new(int64)).Error; err != nil {
			slog.Warn("vulndb is empty. skipping leader election and running daemons directly", "err", err)
			if err := runner.runDaemons(); err != nil {
				slog.Error("could not run daemons", "err", err)
			}
			return
		}
		runner.leaderElector.IfLeader(context.Background(), func() error {
			return runner.runDaemons()
		})
	}()

}
