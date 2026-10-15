// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package listeners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
)

type assetWithProjectAndOrg struct {
	asset         models.Asset
	assetVersions []models.AssetVersion // artifacts are prefetched!
	project       models.Project
	org           models.Org
}

type assetPipelineStep struct {
	topic events.NotifyTopic
	stage string // see DebugOptions.LimitToStages
	span  string
	run   func(ctx context.Context, asset *assetWithProjectAndOrg) error
}

// a step which finished within the interval is not run again unless it is forced.
// must stay below the job retention of the broker, see events.Broker.FinishedSince
const pipelineInterval = 12 * time.Hour

// how many assets the inline pipeline processes at once
const pipelineConcurrency = 10

// the order matters: e.g. the risk has to be recalculated before the tickets are synced
func (runner *DaemonRunner) assetPipelineSteps() []assetPipelineStep {
	return []assetPipelineStep{
		{events.TopicPipelineDeleteOldAssetVersions, StageDeleteOldAssetVersions, "pipeline.delete-old-versions", runner.deleteOldAssetVersions},
		{events.TopicPipelineSyncUpstream, StageSyncUpstream, "pipeline.sync-upstream", runner.syncUpstream},
		{events.TopicPipelineResolveLicenses, StageResolveLicenses, "pipeline.resolve-licenses", runner.resolveLicenses},
		{events.TopicPipelineFindLicenseRisks, StageFindLicenseRisks, "pipeline.find-license-risks", runner.findLicenseRisks},
		{events.TopicPipelineApplyVEXRules, StageApplyVEXRules, "pipeline.apply-vex-rules", runner.applyAssetVEXRules},
		{events.TopicPipelineRecalculateRisk, StageRecalculateRiskForVulnerabilities, "pipeline.recalculate-risk", runner.recalculateRiskForVulnerabilities},
		{events.TopicPipelineResolveFixedVersions, StageResolveFixedVersions, "pipeline.resolve-fixed-versions", runner.resolveFixedVersions},
		{events.TopicPipelineSyncTickets, StageSyncTickets, "pipeline.sync-tickets", runner.syncTickets},
		{events.TopicPipelineResolveTicketDifferences, StageResolveDifferencesInTicketState, "pipeline.resolve-ticket-differences", runner.resolveDifferencesInTicketState},
		{events.TopicPipelineCollectStats, StageCollectStats, "pipeline.collect-stats", runner.collectStats},
	}
}

// assetPipelineJob runs a single step for the asset of the payload - river retries it on its own if it fails
func (runner *DaemonRunner) assetPipelineJob(step int) events.NotifyHandler {
	steps := runner.assetPipelineSteps()
	return job("pipeline error in "+steps[step].stage, func(ctx context.Context, payload events.AssetPipelinePayload) error {
		asset, err := runner.fetchAssetDetails(ctx, payload.AssetID)
		if err != nil {
			return err
		}
		if err := runner.runStep(ctx, steps[step], &asset); err != nil {
			return err
		}
		if !payload.Chain || step+1 == len(steps) {
			return nil
		}
		// call the next step
		return runner.enqueueAssetPipeline(ctx, []uuid.UUID{payload.AssetID}, steps[step+1].topic, payload)
	})
}

// sweepAssetPipeline enqueues the first due step of every asset - the chain takes care of the rest
func (runner *DaemonRunner) sweepAssetPipeline(ctx context.Context) error {
	assetIDs, err := runner.fetchAllAssetIDs(ctx)
	if err != nil {
		return err
	}
	return runner.enqueueAssetPipeline(ctx, assetIDs, runner.assetPipelineSteps()[0].topic, events.AssetPipelinePayload{Chain: true})
}

// enqueueAssetPipeline enqueues for every asset the first due step, starting at the step of from.
// a step is due if the payload is forced or the step did not finish within the pipeline interval.
// without Chain only the step of from is considered.
func (runner *DaemonRunner) enqueueAssetPipeline(ctx context.Context, assetIDs []uuid.UUID, from events.NotifyTopic, payload events.AssetPipelinePayload) error {
	steps := runner.assetPipelineSteps()
	start := slices.IndexFunc(steps, func(step assetPipelineStep) bool { return step.topic == from })
	if start < 0 {
		return fmt.Errorf("%s is not an asset pipeline step", from)
	}
	steps = steps[start:]
	if !payload.Chain {
		steps = steps[:1]
	}

	var finished map[events.NotifyTopic]map[uuid.UUID]struct{}
	var err error
	if !payload.Force {
		finished, err = runner.finishedPipelineSteps(ctx, steps, assetIDs)
		if err != nil {
			return err
		}
	}

	errs := make([]error, 0)
	for _, assetID := range assetIDs {
		for _, step := range steps {
			if _, ok := finished[step.topic][assetID]; ok {
				continue
			}
			p := payload
			p.AssetID = assetID
			if err := runner.broker.Notify(ctx, nil, step.topic, p, nil); err != nil {
				errs = append(errs, fmt.Errorf("could not enqueue %s for asset %s: %w", step.topic, assetID, err))
			}
			break
		}
	}
	return errors.Join(errs...)
}

// finishedPipelineSteps returns per step the assets whose job finished within the pipeline interval - none if forced
func (runner *DaemonRunner) finishedPipelineSteps(ctx context.Context, steps []assetPipelineStep, assetIDs []uuid.UUID) (map[events.NotifyTopic]map[uuid.UUID]struct{}, error) {
	finished := make(map[events.NotifyTopic]map[uuid.UUID]struct{}, len(steps))

	// a single asset narrows the lookup down, otherwise all finished jobs of the step are fetched at once
	var match any
	if len(assetIDs) == 1 {
		match = struct {
			AssetID uuid.UUID `json:"assetId"`
		}{assetIDs[0]}
	}

	since := time.Now().Add(-pipelineInterval)
	for _, step := range steps {
		payloads, err := runner.broker.FinishedSince(ctx, step.topic, since, match)
		if err != nil {
			return nil, fmt.Errorf("could not fetch finished %s jobs: %w", step.topic, err)
		}
		finished[step.topic] = make(map[uuid.UUID]struct{}, len(payloads))
		for _, raw := range payloads {
			var p events.AssetPipelinePayload
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			finished[step.topic][p.AssetID] = struct{}{}
		}
	}
	return finished, nil
}

// RunAssetPipeline runs the pipeline for all assets in this process, bypassing the queue.
// Without forceAll, steps which finished within the pipeline interval are skipped.
func (runner *DaemonRunner) RunAssetPipeline(ctx context.Context, forceAll bool) {
	assetIDs, err := runner.fetchAllAssetIDs(ctx)
	if err != nil {
		monitoring.AlertAndSaveInErrorLog(ctx, nil, monitoring.AlertContext{}, "could not fetch asset ids for the asset pipeline", err)
		return
	}
	runner.runAssetPipelineInline(ctx, assetIDs, forceAll)
}

func (runner *DaemonRunner) RunDaemonPipelineForAsset(ctx context.Context, assetID uuid.UUID) error {
	return runner.runAssetPipelineInline(ctx, []uuid.UUID{assetID}, true)[assetID]
}

// RunDaemonPipelineForAssets runs the pipeline for the given assets and returns the error of every failed asset
func (runner *DaemonRunner) RunDaemonPipelineForAssets(ctx context.Context, assetIDs []uuid.UUID) map[uuid.UUID]error {
	return runner.runAssetPipelineInline(ctx, assetIDs, true)
}

// runAssetPipelineInline runs the steps of every asset one after another and stops an asset at its first failing step.
// inline runs are not recorded as finished jobs - the queue runs those steps again once they are due.
func (runner *DaemonRunner) runAssetPipelineInline(ctx context.Context, assetIDs []uuid.UUID, force bool) map[uuid.UUID]error {
	steps := runner.assetPipelineSteps()
	var finished map[events.NotifyTopic]map[uuid.UUID]struct{}
	var err error
	if !force {
		finished, err = runner.finishedPipelineSteps(ctx, steps, assetIDs)
		if err != nil {
			monitoring.AlertAndSaveInErrorLog(ctx, nil, monitoring.AlertContext{}, "could not fetch finished pipeline steps - running all of them", err)
			finished = nil
		}
	}

	var mu sync.Mutex
	failed := make(map[uuid.UUID]error)
	group := errgroup.Group{}
	group.SetLimit(pipelineConcurrency)
	for _, assetID := range assetIDs {
		group.Go(func() error {
			defer monitoring.RecoverPanicAndSaveInErrorLog(ctx, nil, monitoring.AlertContext{AssetID: assetID}, "asset pipeline panic")
			slog.Info("running asset pipeline", "assetID", assetID)
			err := runner.runStepsForAsset(ctx, assetID, steps, finished)
			if err != nil {
				monitoring.AlertAndSaveInErrorLog(ctx, nil, monitoring.AlertContext{AssetID: assetID}, fmt.Sprintf("pipeline error for asset %s", assetID), err)
				mu.Lock()
				failed[assetID] = err
				mu.Unlock()
			}
			return nil
		})
	}
	group.Wait() // nolint:errcheck // the goroutines never return an error
	return failed
}

func (runner *DaemonRunner) runStepsForAsset(ctx context.Context, assetID uuid.UUID, steps []assetPipelineStep, finished map[events.NotifyTopic]map[uuid.UUID]struct{}) error {
	asset, err := runner.fetchAssetDetails(ctx, assetID)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if _, ok := finished[step.topic][assetID]; ok || !runner.stageEnabled(step.stage) {
			continue
		}
		if err := runner.runStep(ctx, step, &asset); err != nil {
			return err
		}
	}
	return nil
}

// StartBenchmarkJobs runs the asset pipeline over all assets with every database
// write rolled back. stages limits the run to the given pipeline stages, see
// DebugOptions.LimitToStages for the valid names - pass nil to run all of them.
func (runner *DaemonRunner) StartBenchmarkJobs(ctx context.Context, stages []string) {
	runner.SetDebugOptions(DebugOptions{
		DryRun:        true,
		LimitToStages: stages,
	})

	if err := runner.ScanAllAssets(ctx); err != nil {
		monitoring.Alert("could not scan sboms", err)
	}
	runner.RunAssetPipeline(ctx, true)
}

func (runner *DaemonRunner) runStep(ctx context.Context, step assetPipelineStep, asset *assetWithProjectAndOrg) error {
	ctx, span := daemonTracer.Start(ctx, step.span, trace.WithAttributes(
		attribute.String("asset.id", asset.asset.ID.String()),
		attribute.String("asset.slug", asset.asset.Slug),
	))
	defer span.End()

	if err := step.run(ctx, asset); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("%s: %w", step.stage, err)
	}
	return nil
}

func (runner *DaemonRunner) fetchAllAssetIDs(ctx context.Context) ([]uuid.UUID, error) {
	var assetIDs []uuid.UUID
	if err := runner.assetRepository.GetDB(ctx, nil).Model(&models.Asset{}).Pluck("id", &assetIDs).Error; err != nil {
		return nil, fmt.Errorf("could not fetch asset ids: %w", err)
	}
	return assetIDs, nil
}

func (runner *DaemonRunner) fetchAssetDetails(ctx context.Context, assetID uuid.UUID) (assetWithProjectAndOrg, error) {
	ctx, span := daemonTracer.Start(ctx, "pipeline.fetch-details", trace.WithAttributes(attribute.String("asset.id", assetID.String())))
	defer span.End()

	asset, err := runner.assetRepository.Read(ctx, nil, assetID)
	if err != nil {
		return assetWithProjectAndOrg{}, fmt.Errorf("could not fetch asset: %w", err)
	}

	assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(ctx, nil, asset.ID)
	if err != nil {
		return assetWithProjectAndOrg{}, fmt.Errorf("could not fetch asset versions: %w", err)
	}

	if runner.debugOptions.LimitToAssetVersionSlug != "" {
		assetVersions = utils.Filter(assetVersions, func(av models.AssetVersion) bool {
			return av.Slug == runner.debugOptions.LimitToAssetVersionSlug
		})
		if len(assetVersions) == 0 {
			return assetWithProjectAndOrg{}, fmt.Errorf("no asset version with slug %s found", runner.debugOptions.LimitToAssetVersionSlug)
		}
	}

	project, err := runner.projectRepository.Read(ctx, nil, asset.ProjectID)
	if err != nil {
		return assetWithProjectAndOrg{}, fmt.Errorf("could not fetch project: %w", err)
	}
	org, err := runner.orgRepository.Read(ctx, nil, project.OrganizationID)
	if err != nil {
		return assetWithProjectAndOrg{}, fmt.Errorf("could not fetch org: %w", err)
	}

	span.SetAttributes(attribute.Int("asset.versions", len(assetVersions)))
	return assetWithProjectAndOrg{
		asset:         asset,
		assetVersions: assetVersions,
		project:       project,
		org:           org,
	}, nil
}

func parseDisabledExternalEntityProviderIDs() map[string]struct{} {
	// they start with GITLAB_*_DISABLETICKETSYNC=true
	disabledIDs := make(map[string]struct{})
	for _, envVar := range os.Environ() {
		if strings.HasSuffix(envVar, "_DISABLETICKETSYNC=true") {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			providerID := strings.TrimSuffix(strings.TrimPrefix(key, "GITLAB_"), "_DISABLETICKETSYNC")
			disabledIDs[strings.ToUpper(providerID)] = struct{}{}
		}
	}
	return disabledIDs
}

// ticketSyncDisabled reports whether the tickets of the asset must not be touched
func (runner *DaemonRunner) ticketSyncDisabled(asset models.Asset) bool {
	if asset.ExternalEntityProviderID != nil {
		if _, disabled := parseDisabledExternalEntityProviderIDs()[strings.ToUpper(*asset.ExternalEntityProviderID)]; disabled {
			slog.Info("asset connected to disabled external entity provider - skipping ticket sync", "assetID", asset.ID)
			return true
		}
	}
	if !commonint.IsConnectedToThirdPartyIntegration(asset) || runner.DebugMode() {
		slog.Info("asset not connected to third party integration - skipping ticket sync", "assetID", asset.ID)
		return true
	}
	return false
}

// finishTx commits the transaction - or rolls it back in dry run mode
func (runner *DaemonRunner) finishTx(tx shared.DB) {
	if runner.debugOptions.DryRun {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}

func (runner *DaemonRunner) deleteOldAssetVersions(ctx context.Context, a *assetWithProjectAndOrg) error {
	tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
	deleted, err := runner.assetVersionRepository.DeleteOldAssetVersionsOfAsset(ctx, tx, a.asset.ID, 7)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("could not delete old asset versions: %w", err)
	}
	runner.finishTx(tx)
	if deleted > 0 && !runner.debugOptions.DryRun {
		events.NotifyAssetVersionDeleted(ctx, runner.broker, a.asset.ID)
	}

	// Remove just-deleted versions from the in-memory slice.
	// DeleteOldAssetVersionsOfAsset deletes branch versions with
	// last_accessed_at older than 7 days. Without this filter, the following
	// inline steps (e.g. collectStats) iterate over stale artifacts that no
	// longer exist in the DB, causing fk_artifact FK violations when
	// inserting artifact_risk_history rows.
	cutoff := time.Now().AddDate(0, 0, -7)
	a.assetVersions = utils.Filter(a.assetVersions, func(av models.AssetVersion) bool {
		return av.DefaultBranch || av.Type != models.AssetVersionBranch || !av.LastAccessedAt.Before(cutoff)
	})
	return nil
}

func (runner *DaemonRunner) syncUpstream(ctx context.Context, a *assetWithProjectAndOrg) error {
	asset := a.asset
	vexRefs, err := runner.externalReferenceRepository.FindByAssetID(ctx, runner.db, asset.ID)
	if err != nil {
		return fmt.Errorf("could not fetch vex references: %w", err)
	}

	tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
	rules, valid, invalid := runner.scanService.FetchVexFromUpstream(ctx, asset.ID, utils.Map(vexRefs, func(el models.ExternalReference) string {
		return el.URL
	}))
	if err := runner.externalReferenceRepository.SaveBatch(ctx, tx, append(valid, invalid...)); err != nil {
		slog.Error("could not store vex external reference", "err", err)
	}
	if err := runner.ingestVEXRules(ctx, tx, map[uuid.UUID]models.Asset{asset.ID: asset}, map[uuid.UUID][]models.VEXRule{asset.ID: rules}); err != nil {
		slog.Error("could not ingest vex rules", "err", err)
	}
	runner.finishTx(tx)

	errs := make([]error, 0)
	rescannedArtifacts := 0
	for _, assetVersion := range a.assetVersions {
		for _, artifact := range assetVersion.Artifacts {
			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
			// unchanged sboms are skipped, the global scan already covers new cves for them
			rescanned, opened, err := runner.scanService.SyncArtifactUpstreamSBOMSourcesIfChanged(ctx, tx, a.org, a.project, asset, assetVersion, artifact, "system", nil)
			if err != nil {
				slog.Error("failed to sync upstream for artifact", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name, "assetID", asset.ID)
				errs = append(errs, err)
				tx.Rollback()
				continue
			}
			runner.finishTx(tx)
			if rescanned {
				rescannedArtifacts++
				slog.Info("synced changed upstream sboms for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name, "assetID", asset.ID)
				if !runner.debugOptions.DryRun {
					artifactEvent := events.ArtifactPayload{AssetID: asset.ID, AssetVersionName: assetVersion.Name, ArtifactName: artifact.ArtifactName}
					events.NotifySBOMCreatedWithVulns(ctx, runner.broker, artifactEvent, utils.Map(opened, func(v models.DependencyVuln) uuid.UUID { return v.ID }))
				}
			}
		}
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.Int("artifacts.rescanned", rescannedArtifacts))
	if len(errs) > 0 {
		return fmt.Errorf("could not sync upstream: %w", errors.Join(errs...))
	}
	return nil
}

// resolveLicenses fetches the licenses of all components which have none yet - after an upload most of them are known already
func (runner *DaemonRunner) resolveLicenses(ctx context.Context, a *assetWithProjectAndOrg) error {
	if runner.debugOptions.DryRun {
		// the components are saved outside of any transaction
		return nil
	}
	errs := make([]error, 0)
	for _, assetVersion := range a.assetVersions {
		if _, err := runner.componentService.GetAndSaveLicenseInformation(ctx, nil, assetVersion, nil); err != nil {
			slog.Error("could not resolve licenses for asset version", "assetVersionName", assetVersion.Name, "assetID", a.asset.ID, "err", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not resolve licenses: %w", errors.Join(errs...))
	}
	return nil
}

// findLicenseRisks opens a license risk for every component whose license is not valid - and closes the ones whose license became valid
func (runner *DaemonRunner) findLicenseRisks(ctx context.Context, a *assetWithProjectAndOrg) error {
	errs := make([]error, 0)
	for _, assetVersion := range a.assetVersions {
		for _, artifact := range assetVersion.Artifacts {
			if err := runner.findLicenseRisksOfArtifact(ctx, assetVersion, artifact.ArtifactName); err != nil {
				slog.Error("could not find license risks", "artifactName", artifact.ArtifactName, "assetVersionName", assetVersion.Name, "assetID", a.asset.ID, "err", err)
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not find license risks: %w", errors.Join(errs...))
	}
	return nil
}

func (runner *DaemonRunner) findLicenseRisksOfArtifact(ctx context.Context, assetVersion models.AssetVersion, artifactName string) error {
	forest, err := runner.assetVersionService.LoadArtifactSBOMs(ctx, nil, assetVersion, artifactName)
	if err != nil {
		return err
	}
	components, err := runner.componentRepository.FindByIDs(ctx, nil, forest.ComponentIDs())
	if err != nil {
		return fmt.Errorf("could not load components: %w", err)
	}
	// only components with a valid purl carry a version a license applies to
	components = utils.Filter(components, func(component models.Component) bool {
		_, err := packageurl.FromString(component.ID)
		return err == nil
	})

	tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
	if err := runner.licenseRiskService.FindLicenseRisksInComponents(ctx, tx, "system", nil, assetVersion, components, artifactName); err != nil {
		tx.Rollback()
		return err
	}
	runner.finishTx(tx)
	return nil
}

// applyAssetVEXRules re-applies this asset's VEX rules on a schedule, not only at
// rule-creation time or against whatever a scan just found. This is what catches
// a rule that starts matching a vuln later - e.g. an upstream rule ingested by
// syncUpstream above, or a rule whose CEL expression changed since it last ran.
//
// False-positive/accepted rules are only evaluated against currently open vulns
// (closing an already-closed vuln again is a no-op anyway). Reopen rules are the
// mirror image: they only make sense against vulns a previous rule (or a person)
// already accepted, so they're evaluated against accepted vulns instead.
func (runner *DaemonRunner) applyAssetVEXRules(ctx context.Context, a *assetWithProjectAndOrg) error {
	rules, err := runner.vexRuleRepository.FindByAssetID(ctx, runner.db, a.asset.ID)
	if err != nil {
		return fmt.Errorf("could not fetch VEX rules: %w", err)
	}
	runner.applyVEXRules(ctx, a.asset, rules)
	return nil
}

// applyVEXRules mirrors what VEXRuleController.Create does for a single
// newly-created rule, generalized to every rule currently enabled for the asset:
// group rules by the vuln state services.VulnStateForVEXRuleEventType says they
// apply to, fetch one representative vuln per distinct signature in that state,
// let the VEX rule service compute which group events that implies, and persist
// them. Errors are logged rather than returned - a failure for one state
// shouldn't stop the rules of the other states.
func (runner *DaemonRunner) applyVEXRules(ctx context.Context, asset models.Asset, rules []models.VEXRule) {
	rulesByState := make(map[dtos.VulnState][]models.VEXRule)
	for _, rule := range rules {
		state := services.VulnStateForVEXRuleEventType(rule.EventType)
		rulesByState[state] = append(rulesByState[state], rule)
	}

	for state, rulesForState := range rulesByState {
		representativeVulns, err := runner.dependencyVulnRepository.GetVulnsDistinctBySignature(ctx, runner.db, asset.ID, state)
		if err != nil {
			slog.Error("failed to fetch existing vulns for asset", "error", err, "assetID", asset.ID, "state", state)
			continue
		}
		groupEvents, err := services.ComputeGroupVEXRuleEvents(ctx, rulesForState, representativeVulns)
		if err != nil {
			slog.Error("failed to apply VEX rules to vulns", "error", err, "assetID", asset.ID, "state", state)
			continue
		}
		if len(groupEvents) == 0 {
			continue
		}

		tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
		if _, err := runner.dependencyVulnRepository.ApplyGroupEventsAndSave(ctx, tx, groupEvents); err != nil {
			slog.Error("could not save group VEX rule events", "err", err, "assetID", asset.ID, "state", state)
			tx.Rollback()
			continue
		}
		runner.finishTx(tx)
	}
}

func (runner *DaemonRunner) recalculateRiskForVulnerabilities(ctx context.Context, a *assetWithProjectAndOrg) error {
	errs := make([]error, 0)
	for _, assetVersion := range a.assetVersions {
		dependencyVulns, err := runner.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(ctx, nil, assetVersion.Name, assetVersion.AssetID, nil)
		if err != nil {
			slog.Error("failed to get dependency vulns for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
			errs = append(errs, err)
			continue
		}
		if len(dependencyVulns) == 0 {
			continue
		}

		// Use the fetched asset to ensure environmental requirements are loaded
		tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
		if _, err := runner.dependencyVulnService.RecalculateRawRiskAssessment(ctx, tx, "system", dependencyVulns, "System recalculated raw risk assessment", a.asset); err != nil {
			tx.Rollback()
			slog.Error("failed to recalculate raw risk assessment for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
			errs = append(errs, err)
			continue
		}
		runner.finishTx(tx)
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not recalculate risk: %w", errors.Join(errs...))
	}
	return nil
}

func (runner *DaemonRunner) resolveFixedVersions(ctx context.Context, a *assetWithProjectAndOrg) error {
	// get all closed/accepted vulnerabilities for the asset version
	vulnerabilities, err := runner.dependencyVulnRepository.GetAllVulnsByAssetID(ctx, nil, a.asset.ID)
	if err != nil {
		return fmt.Errorf("could not get vulns for asset: %w", err)
	}

	toSaveVulns := make([]models.DependencyVuln, 0)
outer:
	for _, vuln := range vulnerabilities {
		if vuln.ComponentFixedVersion == nil {
			continue
		}

		purls := make([]packageurl.PackageURL, 0)
		for _, el := range vuln.VulnerabilityPath {
			elPURL, err := packageurl.FromString(el)
			if err != nil {
				// slog.Warn("could not parse purl from vulnerability path", "purl", el, "err", err) // this log spams the output and is not useful for the user. We can ignore it.
				continue outer
			}
			purls = append(purls, elPURL)
		}

		directDependencyFixedVersion, err := runner.fixedVersionResolver.ResolveFixedVersions(purls, *vuln.ComponentFixedVersion)
		if err != nil {
			if errors.Is(err, shared.ErrNoFixedVersionAvailable) || errors.Is(err, shared.ErrFixedVersionResolutionUnsupported) {
				continue
			}
			slog.Warn("could not resolve fixed version", "vulnerabilityID", vuln.ID, "err", err)
			continue
		}

		vuln.DirectDependencyFixedVersion = &directDependencyFixedVersion
		toSaveVulns = append(toSaveVulns, vuln)
	}

	if len(toSaveVulns) > 0 {
		tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
		if err := runner.dependencyVulnRepository.SaveBatch(ctx, tx, toSaveVulns); err != nil {
			tx.Rollback()
			return fmt.Errorf("could not save vulns with resolved fixed versions: %w", err)
		}
		runner.finishTx(tx)
	}

	trace.SpanFromContext(ctx).SetAttributes(attribute.Int("vulns.resolved", len(toSaveVulns)))
	return nil
}

func (runner *DaemonRunner) syncTickets(ctx context.Context, a *assetWithProjectAndOrg) error {
	if runner.ticketSyncDisabled(a.asset) {
		return nil
	}
	errs := make([]error, 0)
	for _, assetVersion := range a.assetVersions {
		// No transaction needed: SyncAllIssues delegates to thirdPartyIntegration.CreateIssue/UpdateIssue,
		// which in dry-run mode are intercepted by dryRunIntegration and never reach the DB write inside the real integration.
		for _, err := range []error{
			runner.dependencyVulnService.SyncAllIssues(ctx, a.org, a.project, a.asset, assetVersion, nil),
			runner.firstPartyVulnService.SyncAllIssues(ctx, a.org, a.project, a.asset, assetVersion, nil),
		} {
			if err == nil || errors.Is(err, commonint.ErrNotConnected) {
				continue
			}
			slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", a.asset.ID, "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not sync tickets: %w", errors.Join(errs...))
	}
	return nil
}

func (runner *DaemonRunner) resolveDifferencesInTicketState(ctx context.Context, a *assetWithProjectAndOrg) error {
	if runner.ticketSyncDisabled(a.asset) {
		return nil
	}
	depVulns, err := runner.dependencyVulnRepository.GetAllVulnsByAssetIDWithTicketIDs(ctx, nil, a.asset.ID)
	if err != nil {
		return fmt.Errorf("could not get dependency vulns: %w", err)
	}
	if len(depVulns) == 0 {
		return nil
	}

	trace.SpanFromContext(ctx).SetAttributes(attribute.Int("asset.dep_vulns_with_tickets", len(depVulns)))
	if err := runner.integrationAggregate.CompareIssueStatesAndResolveDifferences(ctx, a.asset, depVulns); err != nil {
		return fmt.Errorf("could not compare ticket states: %w", err)
	}
	return nil
}

func (runner *DaemonRunner) collectStats(ctx context.Context, a *assetWithProjectAndOrg) error {
	errs := make([]error, 0)
	for _, assetVersion := range a.assetVersions {
		for _, artifact := range assetVersion.Artifacts {
			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
			if err := runner.statisticsService.UpdateArtifactRiskAggregation(ctx, tx, &artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
				tx.Rollback()
				slog.Error("could not recalculate risk history", "err", err)
				errs = append(errs, err)
				continue
			}
			runner.finishTx(tx)
			slog.Info("updated statistics for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", artifact.AssetVersionName, "assetID", artifact.AssetID)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not collect stats: %w", errors.Join(errs...))
	}
	return nil
}
