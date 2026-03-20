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

package daemons

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type assetWithProjectAndOrg struct {
	ctx           context.Context // carries the root pipeline.asset span
	asset         models.Asset
	assetVersions []models.AssetVersion // artifacts are prefetched!
	project       models.Project
	org           models.Org
}

type pipelineError struct {
	asset models.Asset
	err   error
}

func (runner *DaemonRunner) runPipeline(ctx context.Context, idsChan <-chan uuid.UUID, errChan chan<- pipelineError) {
	ch := runner.FetchAssetDetails(ctx, idsChan, errChan)
	ch = runner.DeleteOldAssetVersions(ch, errChan)
	ch = runner.ScanAsset(ch, errChan)
	ch = runner.SyncUpstream(ch, errChan)
	ch = runner.AutoReopenTickets(ch, errChan)
	ch = runner.RecalculateRiskForVulnerabilities(ch, errChan)
	ch = runner.ResolveFixedVersions(ch, errChan)
	ch = runner.SyncTickets(ch, errChan)
	ch = runner.ResolveDifferencesInTicketState(ch, errChan)
	ch = runner.CollectStats(ch, errChan)
	utils.WaitForChannelDrain(ch)
	// we can close the error channel now
	// since it is a chan<-pipelineError we can be sure that all errors have been sent
	close(errChan)
}

// this creates a channel which will be used to pipeline asset processing in daemons
func (runner *DaemonRunner) RunAssetPipeline(ctx context.Context, forceAll bool) {
	// fetch all assets from the database
	errChan := make(chan pipelineError, 100)
	runner.collectErrors(errChan)
	var idsChan <-chan uuid.UUID
	if forceAll {
		idsChan = runner.FetchAllAssetIDs(ctx)
	} else {
		idsChan = runner.FetchAssetIDs(ctx)
	}

	runner.runPipeline(ctx, idsChan, errChan)
}

func (runner *DaemonRunner) RunDaemonPipelineForAsset(ctx context.Context, assetID uuid.UUID) error {
	idsChan := make(chan uuid.UUID, 1)
	go func() {
		idsChan <- assetID
		close(idsChan)
	}()

	var pErr pipelineError
	errChan := make(chan pipelineError)
	errCh1, errCh2 := utils.TeeChannel(errChan)
	runner.collectErrors(errCh1)
	wg := make(chan struct{})
	go func() {
		for err := range errCh2 {
			pErr = err
		}
		close(wg)
	}()
	runner.runPipeline(ctx, idsChan, errChan)
	<-wg

	return pErr.err
}

// failStage records err on both the stage span and the root pipeline.asset span, then ends both.
// Call this on every error path before sending to errChan.
func failStage(rootCtx context.Context, stageSpan trace.Span, err error) {
	stageSpan.RecordError(err)
	stageSpan.SetStatus(codes.Error, err.Error())
	stageSpan.End()

	rootSpan := trace.SpanFromContext(rootCtx)
	rootSpan.RecordError(err)
	rootSpan.SetStatus(codes.Error, err.Error())
	rootSpan.End()
}

func (runner *DaemonRunner) collectErrors(input <-chan pipelineError) {
	go func() {
		for assetWithDetails := range input {
			slog.Error("error during asset pipeline", "assetID", assetWithDetails.asset.ID, "err", assetWithDetails.err)

			asset := assetWithDetails.asset
			errMsg := assetWithDetails.err.Error()
			asset.PipelineError = &errMsg
			asset.PipelineLastRun = time.Now()
			err := runner.assetRepository.Save(context.Background(), nil, &asset)
			if err != nil {
				monitoring.Alert("could not save pipeline error to asset", err)
			}
		}
	}()
}

func (runner *DaemonRunner) FetchAllAssetIDs(ctx context.Context) <-chan uuid.UUID {
	out := make(chan uuid.UUID)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("fetch all asset ids panic")
		}()
		var assets []models.Asset
		// fetch ALL asset ids from the database
		err := runner.assetRepository.GetDB(ctx, nil).Model(&models.Asset{}).Select("ID").Find(&assets).Error
		if err != nil {
			monitoring.Alert("could not fetch asset ids. Cannot run runner. This is critical since all background jobs will be stuck.", err)
		}
		for _, asset := range assets {
			out <- asset.ID
		}
	}()
	return out
}

func (runner *DaemonRunner) FetchAssetIDs(ctx context.Context) <-chan uuid.UUID {
	out := make(chan uuid.UUID)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("fetch asset ids panic")
		}()
		var assets []models.Asset
		// fetch ALL asset ids from the database
		err := runner.assetRepository.GetDB(ctx, nil).Model(&models.Asset{}).Where("pipeline_last_run < ?", time.Now().Add(-12*time.Hour)).Select("ID").Find(&assets).Error
		if err != nil {
			monitoring.Alert("could not fetch asset ids. Cannot run runner. This is critical since all background jobs will be stuck.", err)
		}
		for _, asset := range assets {
			out <- asset.ID
		}
	}()
	return out
}

func (runner *DaemonRunner) ResolveFixedVersions(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("resolve fixed versions panic")
		}()
		for assetWithDetails := range input {
			toSaveVulns := make([]models.DependencyVuln, 0)
			// get all closed/accepted vulnerabilities for the asset version
			vulnerabilities, err := runner.dependencyVulnRepository.GetAllVulnsByAssetID(nil, nil, assetWithDetails.asset.ID)
			if err != nil {
				slog.Error("could not get vulns for asset", "assetID", assetWithDetails.asset.ID, "err", err)
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not get vulns for asset: %w", err),
				}
				continue
			}

		outer:
			for _, vuln := range vulnerabilities {
				if vuln.ComponentFixedVersion == nil {
					continue
				}

				purls := make([]packageurl.PackageURL, 0)
				for _, el := range vuln.VulnerabilityPath {
					elPURL, err := packageurl.FromString(el)
					if err != nil {
						slog.Error("could not parse purl from vulnerability path", "purl", el, "err", err)
						continue outer
					}
					purls = append(purls, elPURL)
				}

				directDependencyFixedVersion, err := runner.fixedVersionResolver.ResolveFixedVersions(purls, *vuln.ComponentFixedVersion)
				if err != nil {
					slog.Info("could not resolve fixed version", "vulnerabilityID", vuln.ID, "err", err)
					continue
				}

				vuln.DirectDependencyFixedVersion = &directDependencyFixedVersion
				toSaveVulns = append(toSaveVulns, vuln)
			}

			if len(toSaveVulns) > 0 {
				err = runner.dependencyVulnRepository.SaveBatch(nil, nil, toSaveVulns)
				if err != nil {
					slog.Error("could not save vulns with resolved fixed versions", "assetID", assetWithDetails.asset.ID, "err", err)
					errChan <- pipelineError{
						asset: assetWithDetails.asset,
						err:   fmt.Errorf("could not save vulns with resolved fixed versions: %w", err),
					}
					continue
				}
			}

			out <- assetWithDetails
		}
	}()
	return out
}

// fetches the asset details for each element in the input channel
// This approach is intended to avoid overloading the database with large queries or too many concurrent requests.
func (runner *DaemonRunner) FetchAssetDetails(pipelineCtx context.Context, input <-chan uuid.UUID, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("fetch asset details panic")
		}()
		for assetID := range input {
			// create a root span per asset that will parent all downstream stage spans
			assetCtx, span := daemonTracer.Start(pipelineCtx, "pipeline.asset",
				trace.WithAttributes(attribute.String("asset.id", assetID.String())),
			)

			asset, err := runner.assetRepository.Read(assetCtx, nil, assetID)
			if err != nil {
				slog.Error("could not fetch asset in runner", "assetID", assetID, "err", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "fetch asset failed")
				span.End()
				errChan <- pipelineError{
					asset: models.Asset{Model: models.Model{ID: assetID}},
					err:   fmt.Errorf("could not fetch asset: %w", err),
				}
				continue
			}

			span.SetAttributes(
				attribute.String("asset.slug", asset.Slug),
				attribute.String("asset.name", asset.Name),
			)

			assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(assetCtx, nil, asset.ID)
			if err != nil {
				slog.Error("could not fetch asset versions in runner", "assetID", asset.ID, "err", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "fetch asset versions failed")
				span.End()
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch asset versions: %w", err),
				}
				continue
			}

			if runner.debugOptions.LimitToAssetVersionSlug != "" {
				assetVersions = utils.Filter(assetVersions, func(av models.AssetVersion) bool {
					return av.Slug == runner.debugOptions.LimitToAssetVersionSlug
				})
				if len(assetVersions) == 0 {
					panic("no asset version with slug found")
				}
			}

			project, err := runner.projectRepository.Read(assetCtx, nil, asset.ProjectID)
			if err != nil {
				slog.Error("could not fetch project in runner", "assetID", asset.ID, "err", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "fetch project failed")
				span.End()
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}
			org, err := runner.orgRepository.Read(assetCtx, nil, project.OrganizationID)
			if err != nil {
				slog.Error("could not fetch org in runner", "assetID", asset.ID, "err", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "fetch org failed")
				span.End()
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}

			// mark the asset as processed - so that we do not process it again, even if the pipeline takes longer than an hour
			asset.PipelineLastRun = time.Now()
			asset.PipelineError = nil
			err = runner.assetRepository.Save(assetCtx, nil, &asset)
			if err != nil {
				monitoring.Alert("could not save last pipeline run. The asset will be processed whenever the pipeline runs again (usually 5 minutes)", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "save pipeline run failed")
				span.End()
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}

			// NOTE: the pipeline.asset span is intentionally NOT ended here.
			// It stays open until CollectStats (success) or failStage (failure).
			out <- assetWithProjectAndOrg{
				ctx:           assetCtx,
				asset:         asset,
				assetVersions: assetVersions,
				project:       project,
				org:           org,
			}
		}
	}()
	return out
}

func (runner *DaemonRunner) SyncTickets(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	disabledExternalEntityProviderIDs := parseDisabledExternalEntityProviderIDs()

	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("sync tickets panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if asset.ExternalEntityProviderID != nil {
				if _, disabled := disabledExternalEntityProviderIDs[strings.ToUpper(*asset.ExternalEntityProviderID)]; disabled {
					slog.Info("asset connected to disabled external entity provider - skipping ResolveDifferencesInTicketState", "assetID", asset.ID)
					out <- assetWithDetails
					continue
				}
			}
			if !commonint.IsConnectedToThirdPartyIntegration(asset) || runner.DebugMode() {
				slog.Info("asset not connected to third party integration - skipping SyncTickets", "assetID", asset.ID)
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.sync-tickets")
			errs := make([]error, 0)
			for _, assetVersion := range assetWithDetails.assetVersions {
				err := runner.dependencyVulnService.SyncAllIssues(stageCtx, assetWithDetails.org, assetWithDetails.project, asset, assetVersion)
				if err != nil {
					slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", asset.ID, "error", err)
					errs = append(errs, err)
					continue
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not sync tickets: %v", joined),
				}
				continue
			}

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
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

func (runner *DaemonRunner) ResolveDifferencesInTicketState(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	// parse the disabled external entity provider IDs
	disabledExternalEntityProviderIDs := parseDisabledExternalEntityProviderIDs()

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("resolve differences in ticket state panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if asset.ExternalEntityProviderID != nil {
				if _, disabled := disabledExternalEntityProviderIDs[strings.ToUpper(*asset.ExternalEntityProviderID)]; disabled {
					slog.Info("asset connected to disabled external entity provider - skipping ResolveDifferencesInTicketState", "assetID", asset.ID)
					out <- assetWithDetails
					continue
				}
			}

			if !commonint.IsConnectedToThirdPartyIntegration(asset) || runner.DebugMode() {
				slog.Info("asset not connected to third party integration - skipping ResolveDifferencesInTicketState", "assetID", asset.ID)
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.resolve-ticket-differences")
			depVulns, err := runner.dependencyVulnRepository.GetAllVulnsByAssetIDWithTicketIDs(stageCtx, nil, asset.ID)
			if err != nil {
				slog.Error("could not get dependency vulns for asset", "assetID", asset.ID, "err", err)
				failStage(assetWithDetails.ctx, span, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not get dependency vulns: %w", err),
				}
				continue
			}

			span.SetAttributes(attribute.Int("asset.dep_vulns_with_tickets", len(depVulns)))
			err = runner.integrationAggregate.CompareIssueStatesAndResolveDifferences(stageCtx, asset, depVulns)
			if err != nil {
				slog.Error("could not compare ticket states", "err", err)
				failStage(assetWithDetails.ctx, span, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not compare ticket states: %w", err),
				}
				continue
			}

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) ScanAsset(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("scan panic")
		}()
		frontendURL := os.Getenv("FRONTEND_URL")
		if frontendURL == "" {
			monitoring.Alert("FRONTEND_URL environment variable is not set. ScanAsset stage will fail.", nil)
		}

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.scan")
			errs := make([]error, 0)
			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				bom, err := runner.assetVersionService.LoadFullSBOMGraph(stageCtx, nil, assetVersions[i])
				if err != nil {
					slog.Error("failed to load full sbom", "error", err, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
					errs = append(errs, err)
					continue
				}

				for _, artifact := range artifacts {
					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback

					bom.ClearScope()
					_, _, _, err = runner.scanService.ScanNormalizedSBOM(stageCtx, tx, org, project, asset, assetVersions[i], artifact, bom, "system")

					if err != nil && !errors.Is(err, normalize.ErrNodeNotReachable) {
						tx.Rollback()
						slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						continue
					}
					tx.Commit()

					slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not scan asset: %v", joined),
				}
				continue
			}
			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) SyncUpstream(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("sync upstream panic")
		}()

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.sync-upstream")
			errs := make([]error, 0)

			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback

					if _, _, _, err := runner.scanService.RunArtifactSecurityLifecycle(stageCtx, tx, org, project, asset, assetVersions[i], artifact, "system"); err != nil {
						slog.Error("failed to sync upstream for artifact", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						tx.Rollback()
						continue
					}

					slog.Info("synced upstream for asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)

					tx.Commit()
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not sync upstream: %v", joined),
				}
				continue
			}
			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) CollectStats(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("collect stats panic")
		}()

		for assetWithDetails := range input {
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.collect-stats")
			errs := make([]error, 0)
			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					if err := runner.statisticsService.UpdateArtifactRiskAggregation(stageCtx, &artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
						slog.Error("could not recalculate risk history", "err", err)
						errs = append(errs, err)
						continue
					}
					slog.Info("updated statistics for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", artifact.AssetVersionName, "assetID", artifact.AssetID)
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not collect stats: %v", joined),
				}
				continue
			}

			// Last stage: end both the stage span and the root pipeline.asset span.
			span.End()
			trace.SpanFromContext(assetWithDetails.ctx).End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) RecalculateRiskForVulnerabilities(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("recalculate risk for vulnerabilities panic")
		}()

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.recalculate-risk")
			errs := make([]error, 0)

			for _, assetVersion := range assetVersions {
				dependencyVulns, err := runner.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(stageCtx, nil, assetVersion.Name, assetVersion.AssetID, nil)
				if err != nil {
					slog.Error("failed to get dependency vulns for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					errs = append(errs, err)
					continue
				}

				if len(dependencyVulns) == 0 {
					continue
				}

				// Use asset from assetWithDetails to ensure environmental requirements are loaded
				_, err = runner.dependencyVulnService.RecalculateRawRiskAssessment(stageCtx, nil, "system", dependencyVulns, "System recalculated raw risk assessment", assetWithDetails.asset)
				if err != nil {
					slog.Error("failed to recalculate raw risk assessment for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					errs = append(errs, err)
					continue
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not recalculate risk: %v", joined),
				}
				continue
			}

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) AutoReopenTickets(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("auto reopen tickets panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if asset.VulnAutoReopenAfterDays == nil || *asset.VulnAutoReopenAfterDays <= 0 {
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.auto-reopen-tickets")
			span.SetAttributes(attribute.Int("asset.auto_reopen_after_days", *asset.VulnAutoReopenAfterDays))
			reopenAfterDuration := time.Duration(*asset.VulnAutoReopenAfterDays) * 24 * time.Hour

			vulnerabilities, err := runner.dependencyVulnRepository.GetAllByAssetIDAndState(stageCtx, nil, asset.ID, dtos.VulnStateAccepted, reopenAfterDuration)
			if err != nil {
				slog.Error("failed to get closed/accepted vulnerabilities for asset", "assetID", asset.ID, "error", err)
				failStage(assetWithDetails.ctx, span, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not get closed/accepted vulnerabilities: %w", err),
				}
				continue
			}

			span.SetAttributes(attribute.Int("asset.vulns_to_reopen", len(vulnerabilities)))
			errs := make([]error, 0)
			for _, vuln := range vulnerabilities {
				event := models.NewReopenedEvent(vuln.ID, dtos.VulnTypeDependencyVuln, "system", fmt.Sprintf("Automatically reopened since the vulnerability was accepted more than %d days ago", *asset.VulnAutoReopenAfterDays), false)

				if err := runner.dependencyVulnRepository.ApplyAndSave(stageCtx, nil, &vuln, &event); err != nil {
					slog.Error("failed to apply and save vulnerability event", "vulnerabilityID", vuln.ID, "error", err)
					errs = append(errs, err)
					continue
				} else {
					slog.Info("reopened vulnerability since it was accepted more than the configured time", "vulnerabilityID", vuln.ID, "assetID", asset.ID, "reopenAfterDays", *asset.VulnAutoReopenAfterDays)
				}
			}
			if len(errs) > 0 {
				joined := errors.Join(errs...)
				failStage(assetWithDetails.ctx, span, joined)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not auto-reopen tickets: %v", joined),
				}
				continue
			}

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) DeleteOldAssetVersions(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("delete old asset versions panic")
		}()

		for assetWithDetails := range input {
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.delete-old-versions")
			_, err := runner.assetVersionRepository.DeleteOldAssetVersionsOfAsset(stageCtx, nil, assetWithDetails.asset.ID, 7)
			if err != nil {
				slog.Error("Failed to delete old asset versions", "err", err)
				failStage(assetWithDetails.ctx, span, err)
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not delete old asset versions: %w", err),
				}
				continue
			}

			// Remove just-deleted versions from the in-memory slice.
			// DeleteOldAssetVersionsOfAsset deletes branch versions with
			// last_accessed_at older than 7 days. Without this filter, downstream
			// stages (e.g. CollectStats) iterate over stale artifacts that no
			// longer exist in the DB, causing fk_artifact FK violations when
			// inserting artifact_risk_history rows.
			cutoff := time.Now().AddDate(0, 0, -7)
			assetWithDetails.assetVersions = utils.Filter(assetWithDetails.assetVersions, func(av models.AssetVersion) bool {
				return av.DefaultBranch || av.Type != models.AssetVersionBranch || !av.LastAccessedAt.Before(cutoff)
			})

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner *DaemonRunner) RunResolveFixedVersionsPipeline(ctx context.Context, forceAll bool) error {
	errChan := make(chan pipelineError, 100)
	runner.collectErrors(errChan)
	var idsChan <-chan uuid.UUID
	if forceAll {
		idsChan = runner.FetchAllAssetIDs(ctx)
	} else {
		idsChan = runner.FetchAssetIDs(ctx)
	}

	ch := runner.FetchAssetDetails(ctx, idsChan, errChan)
	ch = runner.ResolveFixedVersions(ch, errChan)
	utils.WaitForChannelDrain(ch)
	close(errChan)
	return nil
}
