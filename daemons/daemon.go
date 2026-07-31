package daemons

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func getLastMirrorTime(ctx context.Context, configService shared.ConfigService, key string) (time.Time, error) {
	var lastMirror struct {
		Time time.Time `json:"time"`
	}

	err := configService.GetJSONConfig(ctx, key, &lastMirror)

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error("could not get last mirror time", "err", err, "key", key)
		return time.Time{}, err
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Info("no last mirror time found. Setting to 0", "key", key)
		return time.Time{}, nil
	}

	return lastMirror.Time, nil
}

func shouldMirror(ctx context.Context, configService shared.ConfigService, key string) bool {
	lastTime, err := getLastMirrorTime(ctx, configService, key)
	if err != nil {
		return false
	}

	return time.Since(lastTime) > 1*time.Hour
}

func markMirrored(ctx context.Context, configService shared.ConfigService, key string) error {
	return configService.SetJSONConfig(ctx, key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func (runner *DaemonRunner) maybeRunAndMark(ctx context.Context, key string, fn func() error) error {
	if shouldMirror(ctx, runner.configService, key) {
		t := time.Now()
		slog.Info("starting daemon", "key", key)
		// always mark as mirrored - even in case of error to avoid endless loops
		err1 := markMirrored(ctx, runner.configService, key)
		err := fn()
		slog.Info("finished daemon", "key", key, "duration", time.Since(t))
		if err != nil {
			return err
		}
		if err1 != nil {
			return err1
		}
	}
	return nil
}

func (runner *DaemonRunner) CleanupOrphanedRecords(ctx context.Context) error {
	if err := runner.artifactRepository.CleanupOrphanedRecords(ctx); err != nil {
		slog.Error("failed to clean up orphaned records", "error", err)
		return err
	}
	return nil
}

func (runner *DaemonRunner) runDaemons(ctx context.Context) {
	if err := runner.maybeRunAndMark(ctx, "maintain.cleanup", func() error {
		return runner.CleanupOrphanedRecords(ctx)
	}); err != nil {
		slog.Error("could not clean up orphaned records", "err", err)
	}

	if err := runner.maybeRunAndMark(ctx, "vulndb.opensourceinsights", func() error {
		return runner.UpdateOpenSourceInsightInformation(ctx)
	}); err != nil {
		slog.Error("could not update deps dev information", "err", err)
	}

	if err := runner.maybeRunAndMark(ctx, "vulndb.vulndb", func() error {
		return runner.UpdateVulnDB(ctx)
	}); err != nil {
		slog.Error("could not update vuln db", "err", err)
	}

	if err := runner.maybeRunAndMark(ctx, "vulndb.fixedVersions", func() error {
		return runner.UpdateFixedVersions(ctx)
	}); err != nil {
		slog.Error("could not update fixed versions", "err", err)
	}

	if err := runner.maybeRunAndMark(ctx, "vulndb.directDependencyFixedVersion", func() error {
		return runner.RunResolveFixedVersionsPipeline(ctx, false)
	}); err != nil {
		slog.Error("could not resolve direct depend	ency fixed versions", "err", err)
	}
}
