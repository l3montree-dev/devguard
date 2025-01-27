package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/leaderelection"
	"github.com/l3montree-dev/devguard/internal/database"
	"gorm.io/gorm"
)

var lastMirror struct {
	Time time.Time `json:"time"`
}

func Start(db database.DB) {
	configService := config.NewService(db)
	leaderElector := leaderelection.NewDatabaseLeaderElector(configService)

	// only run this function if leader
	leaderElector.IfLeader(context.Background(), func() error {
		err := configService.GetJSONConfig("vulndb.lastMirror", &lastMirror)

		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Error("could not get last mirror time", "err", err)
			return nil
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Info("no last mirror time found. Setting to 0")
			lastMirror.Time = time.Time{}
		}

		// we only update the vulnerability database each 6 hours.
		// thus there is no need to recalculate the risk or anything earlier
		if time.Since(lastMirror.Time) > 6*time.Hour {
			// first update the vulndb
			// this will give us the latest cves, cwes, exploits and affected components

			if err := UpdateVulnDB(db); err != nil {
				slog.Error("could not update vulndb", "err", err)
				return nil
			}

			// after we have a fresh vulndb we can update the flaws.
			// we save data inside the flaws table: ComponentDepth and ComponentFixedVersion
			// those need to be updated before recalculating the risk
			if err := UpdateComponentProperties(db); err != nil {
				slog.Error("could not update component properties", "err", err)
				return nil
			}

			// finally, recalculate the risk.
			if err := RecalculateRisk(db); err != nil {
				slog.Error("could not recalculate risk", "err", err)
				return nil
			}

			// as a last step - update the statistics
			if err := UpdateStatistics(db); err != nil {
				slog.Error("could not update statistics", "err", err)
				return nil
			}
			// wait for 6 hours before updating the vulndb again
			time.Sleep(6 * time.Hour)
		}
		// wait for 5 minutes before checking again
		time.Sleep(5 * time.Minute)
		return nil
	})
}
