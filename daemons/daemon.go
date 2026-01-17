package daemons

import (
	"log/slog"
	"time"

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

func (runner *DaemonRunner) maybeRunAndMark(key string, fn func() error) error {
	if shouldMirror(runner.configService, key) {
		// always mark as mirrored - even in case of error to avoid endless loops
		err1 := markMirrored(runner.configService, key)
		err := fn()
		if err != nil {
			return err
		}
		if err1 != nil {
			return err1
		}
	}
	return nil
}

func (runner *DaemonRunner) runDaemons() {
	if err := runner.maybeRunAndMark("vulndb.opensourceinsights", runner.UpdateOpenSourceInsightInformation); err != nil {
		slog.Error("could not update deps dev information", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.vulndb", runner.UpdateVulnDB); err != nil {
		slog.Error("could not update vuln db", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.fixedVersions", runner.UpdateFixedVersions); err != nil {
		slog.Error("could not update fixed versions", "err", err)
	}
}
