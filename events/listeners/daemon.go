package listeners

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
	return runner.externalEntityProviderService.CollectGarbage(ctx)
}

func (runner *DaemonRunner) CollectDebReleaseTimes(ctx context.Context) error {
	return runner.debReleaseTimeService.Collect(ctx)
}

// job wraps fn into a queue handler: it bounds the run time, unmarshals the payload and alerts if fn fails.
// A record deleted in the meantime is no failure - there is nothing left to do, so the job is not retried.
func job[P events.Payload](errMsg string, fn func(ctx context.Context, payload P) error) events.NotifyHandler {
	return func(ctx context.Context, raw json.RawMessage) error {
		ctx, cancel := context.WithTimeout(ctx, events.HandlerTimeout)
		defer cancel()

		var payload P
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &payload); err != nil {
				return fmt.Errorf("could not unmarshal payload: %w", err)
			}
		}
		err := fn(ctx, payload)
		if err == nil || shared.IsNotFound(err) {
			return nil
		}
		monitoring.AlertAndSaveInErrorLog(ctx, nil, payload.AlertContext(), errMsg, err)
		return err
	}
}

// enqueues the step for every asset which did not resolve its fixed versions within the pipeline interval
func (runner *DaemonRunner) runDirectDependencyFixedVersions(ctx context.Context) error {
	assetIDs, err := runner.fetchAllAssetIDs(ctx)
	if err != nil {
		return err
	}
	return runner.enqueueDueAssetPipeline(ctx, assetIDs, events.TopicPipelineResolveFixedVersions)
}

func (runner *DaemonRunner) RegisterJobs(schedule bool) error {
	jobs := []struct {
		topic   events.NotifyTopic
		cron    string // empty: not scheduled, triggered by the previous step of a chain
		errMsg  string
		handler func(ctx context.Context) error
		next    *events.NotifyTopic // notified once the handler succeeded - each step of a chain is retried on its own
	}{
		// the hourly daemons are staggered to avoid running all of them at once
		{events.TopicVEXRuleRecommendations, "0 * * * *", "could not run VEX rule recommendation daemon", runner.RunVEXRuleRecommendationDaemon, nil},
		{events.TopicCleanupOrphanedRecords, "5 * * * *", "could not clean up orphaned records", runner.CleanupOrphanedRecords, nil},
		{events.TopicSBOMGarbageCollection, "10 * * * *", "could not collect sbom garbage", runner.CollectSBOMGarbage, nil},
		{events.TopicOpenSourceInsights, "15 * * * *", "could not update open source insight information", runner.UpdateOpenSourceInsightInformation, nil},
		{events.TopicExternalEntityGarbage, "20 * * * *", "could not collect external entity garbage", runner.CollectExternalEntityGarbage, nil},
		{events.TopicCollectDebReleaseTimes, "40 */12 * * *","could not collect debian release times", runner.CollectDebReleaseTimes, nil},
		// the sweep only enqueues the due steps of every asset, see assetPipelineSteps
		{events.TopicAssetPipeline, "*/5 * * * *", "could not sweep asset pipeline", runner.sweepAssetPipeline, nil},

		{events.TopicVulnDB, "30 * * * *", "could not update vulndb", runner.UpdateVulnDB, new(events.TopicScan)},
		{events.TopicScan, "", "could not scan sboms", runner.ScanAllAssets, new(events.TopicFixedVersions)},
		{events.TopicFixedVersions, "", "could not update fixed versions", runner.UpdateFixedVersions, new(events.TopicDirectDependencyFixedVersion)},
		{events.TopicDirectDependencyFixedVersion, "", "could not resolve direct dependency fixed versions", runner.runDirectDependencyFixedVersions, nil},
	}

	for _, daemon := range jobs {
		handler := job(daemon.errMsg, func(ctx context.Context, _ events.EmptyPayload) error {
			if err := daemon.handler(ctx); err != nil {
				return err
			}
			if daemon.next == nil {
				return nil
			}
			return runner.broker.Notify(ctx, nil, *daemon.next, nil, nil)
		})
		if err := runner.broker.Listen(daemon.topic, handler); err != nil {
			return fmt.Errorf("could not listen on %s: %w", daemon.topic, err)
		}
		if !schedule || daemon.cron == "" {
			continue
		}
		if err := runner.broker.Schedule(daemon.topic, daemon.cron); err != nil {
			return fmt.Errorf("could not schedule %s: %w", daemon.topic, err)
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
		{events.TopicSBOMCreated, runner.enqueueStep(events.TopicPipelineResolveLicenses)},
		{events.TopicSBOMCreated, runner.artifactJob("could not handle sbom created event", runner.sendSBOMCreatedEvent)},
		{events.TopicDependencyVulnsDetected, runner.artifactJob("could not handle dependency vulns detected event", runner.sendDependencyVulnsDetectedEvent)},
		// the ticket sync is followed by the ticket differences and the stats
		{events.TopicFirstPartyScanned, runner.enqueueStep(events.TopicPipelineSyncTickets)},
		{events.TopicFirstPartyScanned, runner.artifactJob("could not handle first party vulns detected event", runner.sendFirstPartyVulnsDetectedEvent)},
		{events.TopicVEXRuleCreated, runner.enqueueStep(events.TopicPipelineSyncTickets)},
		{events.TopicVEXRuleDeleted, runner.enqueueStep(events.TopicPipelineSyncTickets)},
		{events.TopicAssetTicketSettingsChanged, runner.enqueueStep(events.TopicPipelineSyncTickets)},
		{events.TopicArtifactDeleted, runner.enqueueCleanup()},
		{events.TopicAssetVersionDeleted, runner.enqueueCleanup()},
	}
	for _, listener := range listeners {
		if err := runner.broker.Listen(listener.topic, listener.handler); err != nil {
			return fmt.Errorf("could not listen on %s: %w", listener.topic, err)
		}
	}
	return nil
}
