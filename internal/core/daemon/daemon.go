package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/leaderelection"
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

func Start(db core.DB) {
	configService := config.NewService(db)
	leaderElector := leaderelection.NewDatabaseLeaderElector(configService)
	// only run this function if leader
	leaderElector.IfLeader(context.Background(), func() error {
		// we only update the vulnerability database each 6 hours.
		// thus there is no need to recalculate the risk or anything earlier
		slog.Info("starting background jobs", "time", time.Now())
		var start time.Time = time.Now()
		// update deps dev
		err := UpdateDepsDevInformation(db)
		if err != nil {
			slog.Error("could not update deps dev information", "err", err)
			return nil
		}
		slog.Info("deps dev information updated", "duration", time.Since(start))

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
			if err := ScanAssetVersions(db); err != nil {
				slog.Error("could not update scan", "err", err)
				return nil
			}
			if err := markMirrored(configService, "vulndb.scan"); err != nil {
				slog.Error("could not mark vulndb.scan as mirrored", "err", err)
			}
			slog.Info("scan updated", "duration", time.Since(start))
		}

		// after we have a fresh vulndb we can update the dependencyVulns.
		// we save data inside the dependency_vulns table: ComponentDepth and ComponentFixedVersion
		// those need to be updated before recalculating the risk
		if shouldMirror(configService, "vulndb.componentProperties") {
			start = time.Now()
			if err := UpdateComponentProperties(db); err != nil {
				slog.Error("could not update component properties", "err", err)
				return nil
			}
			if err := markMirrored(configService, "vulndb.componentProperties"); err != nil {
				slog.Error("could not mark vulndb.componentProperties as mirrored", "err", err)
			}
			slog.Info("component properties updated", "duration", time.Since(start))
		}

		if shouldMirror(configService, "vulndb.risk") {
			start = time.Now()
			// finally, recalculate the risk.
			if err := RecalculateRisk(db); err != nil {
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
			if err := SyncTickets(db); err != nil {
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

		// wait for 5 minutes before checking again
		time.Sleep(5 * time.Minute)
		return nil
	})
}
