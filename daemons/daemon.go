package daemons

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/monitoring"
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
	} else if shared.IsNotFound(err) {
		slog.Info("no last mirror time found. Setting to 0", "key", key)
		return time.Time{}, nil
	}

	return lastMirror.Time, nil
}

// CollectSBOMGarbage removes subtrees no SBOM can reach any more.
//
// Content addressing never updates or deletes an edge in place, so every
// superseded revision of an SBOM leaves its old spine behind. Only reachability
// from the sboms table distinguishes those from subtrees another SBOM still
// shares, which is why this is a mark and sweep rather than reference counting.
//
// The sweep is safe to run alongside ingest: SaveTree writes a tree and the row
// referencing it in one transaction, so a tree is never visible here without
// the row that keeps it alive.
func (runner *DaemonRunner) CollectSBOMGarbage(ctx context.Context) error {
	deleted, err := runner.sbomRepository.CollectGarbage(ctx, nil)
	if err != nil {
		slog.Error("failed to collect sbom garbage", "error", err)
		return err
	}
	slog.Info("collected sbom garbage", "deletedRows", deleted)
	return nil
}

func (runner *DaemonRunner) CleanupOrphanedRecords(ctx context.Context) error {
	if err := runner.artifactRepository.CleanupOrphanedRecords(ctx); err != nil {
		slog.Error("failed to clean up orphaned records", "error", err)
		return err
	}
	return nil
}

func (runner *DaemonRunner) RunScanDaemon(ctx context.Context) error {
	if err := runner.ScanAllAssets(ctx); err != nil {
		slog.Error("failed to run scan daemon", "error", err)
		return err
	}
	return nil
}

func (runner *DaemonRunner) CollectExternalEntityGarbage(ctx context.Context) error {
	if err := runner.externalEntityProviderService.CollectGarbage(ctx); err != nil {
		slog.Error("failed to collect external entity garbage", "error", err)
		return err
	}
	return nil
}

// jobTimeout bounds every daemon job - river does not cancel the handlers itself (see events.Queue)
const jobTimeout = 2 * time.Hour

// daemonJob wraps a daemon into a queue handler with a timeout and alerting
func daemonJob(errMsg string, fn func(ctx context.Context) error) events.NotifyHandler {
	return func(ctx context.Context, _ json.RawMessage) error {
		ctx, cancel := context.WithTimeout(ctx, jobTimeout)
		defer cancel()
		if err := fn(ctx); err != nil {
			monitoring.AlertAndSaveInErrorLog(ctx, nil, monitoring.AlertContext{}, errMsg, err)
			return err
		}
		return nil
	}
}

// the vulndb chain: vulndb -> scan -> fixed versions -> direct dependency fixed versions.
// each step notifies the next one on success - therefore each step is retried on its own.
func (runner *DaemonRunner) runVulnDB(ctx context.Context) error {
	if err := runner.UpdateVulnDB(ctx); err != nil {
		return err
	}
	return runner.broker.Notify(ctx, nil, events.TopicScan, nil, nil)
}

func (runner *DaemonRunner) runScan(ctx context.Context) error {
	if err := runner.ScanAllAssets(ctx); err != nil {
		return err
	}
	return runner.broker.Notify(ctx, nil, events.TopicFixedVersions, nil, nil)
}

func (runner *DaemonRunner) runFixedVersions(ctx context.Context) error {
	if err := runner.UpdateFixedVersions(ctx); err != nil {
		return err
	}
	return runner.broker.Notify(ctx, nil, events.TopicDirectDependencyFixedVersion, nil, nil)
}

// enqueues the step for every asset which did not resolve its fixed versions within the pipeline interval
func (runner *DaemonRunner) runDirectDependencyFixedVersions(ctx context.Context) error {
	assetIDs, err := runner.fetchAllAssetIDs(ctx)
	if err != nil {
		return err
	}
	return runner.enqueueAssetPipeline(ctx, assetIDs, events.TopicPipelineResolveFixedVersions, events.AssetPipelinePayload{})
}

func (runner *DaemonRunner) RegisterJobs(schedule bool) error {
	jobs := []struct {
		topic   events.NotifyTopic
		cron    string // empty: not scheduled, triggered by the previous step of a chain
		errMsg  string
		handler func(ctx context.Context) error
	}{
		// the hourly daemons are staggered to avoid running all of them at once
		{events.TopicVEXRuleRecommendations, "0 * * * *", "could not run VEX rule recommendation daemon", runner.RunVEXRuleRecommendationDaemon},
		{events.TopicCleanupOrphanedRecords, "5 * * * *", "could not clean up orphaned records", runner.CleanupOrphanedRecords},
		{events.TopicSBOMGarbageCollection, "10 * * * *", "could not collect sbom garbage", runner.CollectSBOMGarbage},
		{events.TopicOpenSourceInsights, "15 * * * *", "could not update open source insight information", runner.UpdateOpenSourceInsightInformation},
		{events.TopicExternalEntityGarbage, "20 * * * *", "could not collect external entity garbage", runner.CollectExternalEntityGarbage},
		// the sweep only enqueues the due steps of every asset, see assetPipelineSteps
		{events.TopicAssetPipeline, "*/5 * * * *", "could not sweep asset pipeline", runner.sweepAssetPipeline},

		{events.TopicVulnDB, "30 * * * *", "could not update vulndb", runner.runVulnDB},
		{events.TopicScan, "", "could not scan sboms", runner.runScan},
		{events.TopicFixedVersions, "", "could not update fixed versions", runner.runFixedVersions},
		{events.TopicDirectDependencyFixedVersion, "", "could not resolve direct dependency fixed versions", runner.runDirectDependencyFixedVersions},
	}

	for _, job := range jobs {
		if err := runner.broker.Listen(job.topic, daemonJob(job.errMsg, job.handler)); err != nil {
			return fmt.Errorf("could not listen on %s: %w", job.topic, err)
		}
		if !schedule || job.cron == "" {
			continue
		}
		if err := runner.broker.Schedule(job.topic, job.cron); err != nil {
			return fmt.Errorf("could not schedule %s: %w", job.topic, err)
		}
	}

	// the asset pipeline steps are never scheduled - the sweep or an event enqueues them per asset
	for i, step := range runner.assetPipelineSteps() {
		if err := runner.broker.Listen(step.topic, runner.assetPipelineJob(i)); err != nil {
			return fmt.Errorf("could not listen on %s: %w", step.topic, err)
		}
	}

	// what follows the domain events - see events/domain_events.go
	listeners := []struct {
		topic   events.NotifyTopic
		handler events.NotifyHandler
	}{
		{events.TopicSBOMCreated, runner.enqueueStep(events.TopicPipelineResolveLicenses, true)},
		{events.TopicSBOMCreated, runner.artifactJob("could not handle sbom created event", runner.sendSBOMCreatedEvent)},
		{events.TopicDependencyVulnsDetected, runner.artifactJob("could not handle dependency vulns detected event", runner.sendDependencyVulnsDetectedEvent)},
		{events.TopicFirstPartyScanned, runner.enqueueStep(events.TopicPipelineSyncTickets, false)},
		{events.TopicFirstPartyScanned, runner.artifactJob("could not handle first party vulns detected event", runner.sendFirstPartyVulnsDetectedEvent)},
		{events.TopicVEXRuleCreated, runner.enqueueStep(events.TopicPipelineSyncTickets, false)},
		{events.TopicVEXRuleCreated, runner.enqueueStep(events.TopicPipelineCollectStats, false)},
		{events.TopicVEXRuleDeleted, runner.enqueueStep(events.TopicPipelineSyncTickets, false)},
		{events.TopicVEXRuleDeleted, runner.enqueueStep(events.TopicPipelineCollectStats, false)},
		{events.TopicAssetTicketSettingsChanged, runner.enqueueStep(events.TopicPipelineSyncTickets, false)},
		{events.TopicArtifactDeleted, runner.cleanupOrphanedRecords},
		{events.TopicAssetVersionDeleted, runner.cleanupOrphanedRecords},
	}
	for _, listener := range listeners {
		if err := runner.broker.Listen(listener.topic, listener.handler); err != nil {
			return fmt.Errorf("could not listen on %s: %w", listener.topic, err)
		}
	}
	return nil
}
