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
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
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
	// scan asset will apply all vex rules
	ch = runner.ScanAsset(ch, errChan)
	ch = runner.SyncUpstream(ch, errChan)
	ch = runner.ApplyVEXRules(ch, errChan)
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
			monitoring.Alert(fmt.Sprintf("pipeline error for asset %s: %v", assetWithDetails.asset.ID, assetWithDetails.err), assetWithDetails.err)

			asset := assetWithDetails.asset
			errMsg := assetWithDetails.err.Error()
			asset.PipelineError = &errMsg
			asset.PipelineLastRun = time.Now()
			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
			err := runner.assetRepository.Save(context.Background(), tx, &asset)
			if err != nil {
				tx.Rollback()
				monitoring.Alert("could not save pipeline error to asset", err)
				continue
			}
			if runner.debugOptions.DryRun {
				tx.Rollback()
			} else {
				tx.Commit()
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
			if !runner.stageEnabled("ResolveFixedVersions") {
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.resolve-fixed-versions")
			toSaveVulns := make([]models.DependencyVuln, 0)
			// get all closed/accepted vulnerabilities for the asset version
			vulnerabilities, err := runner.dependencyVulnRepository.GetAllVulnsByAssetID(stageCtx, nil, assetWithDetails.asset.ID)
			if err != nil {
				slog.Error("could not get vulns for asset", "assetID", assetWithDetails.asset.ID, "err", err)
				failStage(assetWithDetails.ctx, span, err)
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
						// slog.Warn("could not parse purl from vulnerability path", "purl", el, "err", err) // this log spams the output and is not useful for the user. We can ignore it.
						continue outer
					}
					purls = append(purls, elPURL)
				}

				directDependencyFixedVersion, err := runner.fixedVersionResolver.ResolveFixedVersions(purls, *vuln.ComponentFixedVersion)
				if err != nil {
					// slog.Debug("could not resolve fixed version", "vulnerabilityID", vuln.ID, "err", err) // this log spams the output and is not useful for the user. We can ignore it.
					continue
				}

				vuln.DirectDependencyFixedVersion = &directDependencyFixedVersion
				toSaveVulns = append(toSaveVulns, vuln)
			}

			if len(toSaveVulns) > 0 {
				tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
				err = runner.dependencyVulnRepository.SaveBatch(stageCtx, tx, toSaveVulns)
				if err != nil {
					tx.Rollback()
					slog.Error("could not save vulns with resolved fixed versions", "assetID", assetWithDetails.asset.ID, "err", err)
					failStage(assetWithDetails.ctx, span, err)
					errChan <- pipelineError{
						asset: assetWithDetails.asset,
						err:   fmt.Errorf("could not save vulns with resolved fixed versions: %w", err),
					}
					continue
				}
				if runner.debugOptions.DryRun {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}

			span.SetAttributes(attribute.Int("vulns.resolved", len(toSaveVulns)))
			span.End()
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
			slog.Info("running asset pipeline", "assetID", assetID, "traceID", span.SpanContext().TraceID().String())

			fetchCtx, fetchSpan := daemonTracer.Start(assetCtx, "pipeline.fetch-details")

			asset, err := runner.assetRepository.Read(fetchCtx, nil, assetID)
			if err != nil {
				slog.Error("could not fetch asset in runner", "assetID", assetID, "err", err)
				failStage(assetCtx, fetchSpan, err)
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

			assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(fetchCtx, nil, asset.ID)
			if err != nil {
				slog.Error("could not fetch asset versions in runner", "assetID", asset.ID, "err", err)
				failStage(assetCtx, fetchSpan, err)
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

			project, err := runner.projectRepository.Read(fetchCtx, nil, asset.ProjectID)
			if err != nil {
				slog.Error("could not fetch project in runner", "assetID", asset.ID, "err", err)
				failStage(assetCtx, fetchSpan, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}
			org, err := runner.orgRepository.Read(fetchCtx, nil, project.OrganizationID)
			if err != nil {
				slog.Error("could not fetch org in runner", "assetID", asset.ID, "err", err)
				failStage(assetCtx, fetchSpan, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}

			// mark the asset as processed - so that we do not process it again, even if the pipeline takes longer than an hour
			asset.PipelineLastRun = time.Now()
			asset.PipelineError = nil
			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
			err = runner.assetRepository.Save(fetchCtx, tx, &asset)
			if err != nil {
				tx.Rollback()
				monitoring.Alert("could not save last pipeline run. The asset will be processed whenever the pipeline runs again (usually 5 minutes)", err)
				failStage(assetCtx, fetchSpan, err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}
			if runner.debugOptions.DryRun {
				tx.Rollback()
			} else {
				tx.Commit()
			}

			fetchSpan.SetAttributes(attribute.Int("asset.versions", len(assetVersions)))
			fetchSpan.End()

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
			if !runner.stageEnabled("SyncTickets") {
				out <- assetWithDetails
				continue
			}
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
				// No transaction needed: SyncAllIssues delegates to thirdPartyIntegration.CreateIssue/UpdateIssue,
				// which in dry-run mode are intercepted by dryRunIntegration and never reach the DB write inside the real integration.
				err := runner.dependencyVulnService.SyncAllIssues(stageCtx, assetWithDetails.org, assetWithDetails.project, asset, assetVersion, nil)
				if errors.Is(err, commonint.ErrNotConnected) {
					// swallow if error
					continue
				}

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
			if !runner.stageEnabled("ResolveDifferencesInTicketState") {
				out <- assetWithDetails
				continue
			}
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
			if len(depVulns) == 0 {
				slog.Info("no dependency vulns with tickets found for asset - skipping ResolveDifferencesInTicketState", "assetID", asset.ID)
				span.End()
				out <- assetWithDetails
				continue
			}

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

func (runner *DaemonRunner) NewScanAsset() error {
	ctx := context.Background()
	conn, err := runner.pgxpool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	slog.Info("snapshotting sboms table")

	sbomRows, err := conn.Query(ctx, `
		SELECT MD5(
			s.artifact_name || 
			s.asset_version_name || 
			s.asset_id::text)::uuid as artifact, 
		s.root_subtree_hash 
		FROM sboms s;`)
	if err != nil {
		return fmt.Errorf("could not snapshot sboms table: %w", err)
	}
	defer sbomRows.Close()

	sbomSnapshot := make(map[uuid.UUID][]uuid.UUID, 4000)
	var artifact, rootHash uuid.UUID
	for sbomRows.Next() {
		err = sbomRows.Scan(&artifact, &rootHash)
		if err != nil {
			return fmt.Errorf("could not scan sbom row: %w", err)
		}
		sbomSnapshot[artifact] = append(sbomSnapshot[artifact], rootHash)
	}
	sbomRows.Close()
	if err := sbomRows.Err(); err != nil {
		return fmt.Errorf("error when scanning sbom rows: %w", err)
	}

	slog.Info("start collecting all dependencies")
	start := time.Now()
	purlRows, err := conn.Query(ctx, `SELECT DISTINCT component_id FROM sbom_merkle_nodes;`)
	if err != nil {
		return err
	}

	allDependencies := make([]packageurl.PackageURL, 0, 15_000)
	rawPurlsByCanonical := make(map[string][]string, 15_000)
	var purl string
	var parsedPurl packageurl.PackageURL
	for purlRows.Next() {
		err = purlRows.Scan(&purl)
		if err != nil {
			return err
		}
		parsedPurl, err = packageurl.FromString(purl)
		if err != nil {
			continue
		}
		canonicalPurl := parsedPurl.String()
		if _, ok := rawPurlsByCanonical[canonicalPurl]; !ok {
			allDependencies = append(allDependencies, parsedPurl)
		}
		rawPurlsByCanonical[canonicalPurl] = append(rawPurlsByCanonical[canonicalPurl], purl)
	}
	purlRows.Close()
	if err := purlRows.Err(); err != nil {
		return err
	}
	slog.Info("finished reading all dependencies", "amount", len(allDependencies), "time", time.Since(start))

	purlMatcher := scan.NewPurlComparer(runner.db, new(int(0)), scan.WithPreloads())

	slog.Info("start matching purls to affected components")
	start = time.Now()
	candidates, err := purlMatcher.GetAffectedComponentsBatch(ctx, allDependencies)
	if err != nil {
		return fmt.Errorf("could not match purls: %w", err)
	}
	slog.Info("finished matching purls to affected components", "candidates", len(candidates), "time", time.Since(start))

	allDependencies = nil
	// represents a row in the temporary pivot table
	type purlAffectedComponent struct {
		purl                string
		affectedComponentID int64
		fixedVersion        *string
	}

	purlAffectedComponents := make([]purlAffectedComponent, 0, len(candidates))
	isPurlAffected := make(map[string]struct{}, len(candidates)/2)
	for _, candidate := range candidates {
		if len(candidate.Components) == 0 {
			continue
		}
		for _, rawPurl := range rawPurlsByCanonical[candidate.Purl.String()] {
			isPurlAffected[rawPurl] = struct{}{}
			for i := range candidate.Components {
				fixed := candidate.Components[i].SemverFixed
				if fixed == nil {
					fixed = candidate.Components[i].VersionFixed
				}
				purlAffectedComponents = append(purlAffectedComponents, purlAffectedComponent{
					purl:                rawPurl,
					affectedComponentID: candidate.Components[i].ID,
					fixedVersion:        fixed,
				})
			}
		}
	}

	affectedPurls := utils.DeduplicateSlice(purlAffectedComponents, func(purl purlAffectedComponent) string { return purl.purl })

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// make that temporary when not testing
	_, err = tx.Exec(ctx, `
	CREATE TABLE purl_mapping (
		purl text,
		affected_component_id bigint,
		fixed_version text
	);`)
	if err != nil {
		return fmt.Errorf("could not create temp table for purl Mapping: %w", err)
	}

	start = time.Now()
	slog.Info("start copying into temporary table")
	// use canonical purls to ensure consistent matching
	purlMemo := make(map[string]string, len(rawPurlsByCanonical))
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"purl_mapping"}, []string{"purl", "affected_component_id", "fixed_version"}, pgx.CopyFromSlice(len(purlAffectedComponents), func(i int) ([]any, error) {
		return []any{canonicalPurl(purlAffectedComponents[i].purl, purlMemo), purlAffectedComponents[i].affectedComponentID, purlAffectedComponents[i].fixedVersion}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy rows into temporary table: %w", err)
	}

	purlAffectedComponents = nil

	// precompute the join to the cve ids
	_, err = tx.Exec(ctx, `
	CREATE TABLE purl_to_cves AS (
		SELECT DISTINCT pm.purl,pm.fixed_version, cac.cve_id 
		FROM purl_mapping pm 
		JOIN cve_affected_component cac
		ON cac.affected_component_id = pm.affected_component_id
	);
	
	DROP TABLE public.purl_mapping;
	ALTER TABLE public.purl_to_cves RENAME TO purl_mapping;`)
	if err != nil {
		return fmt.Errorf("could not convert affected component mapping to cve id mapping: %w", err)
	}

	_, err = tx.Exec(ctx, `
	CREATE INDEX ON public.purl_mapping (purl,cve_id,fixed_version);`)
	if err != nil {
		return fmt.Errorf("could not enforce primary key on purl_mapping table: %w", err)
	}

	slog.Info("successfully populated temporary table", "time", time.Since(start))

	_, err = tx.Exec(ctx, `DROP TABLE IF EXISTS vuln_paths; DROP TABLE IF EXISTS new_dependency_vulns;`)
	if err != nil {
		return fmt.Errorf("could not drop table for vuln paths: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		panic(err)
	}

	slog.Info("start scanning affected purls", "amount", len(affectedPurls))
	start = time.Now()

	scanTx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not start scan transaction: %w", err)
	}
	defer scanTx.Rollback(ctx)

	_, err = scanTx.Exec(ctx, `
			CREATE TABLE vuln_paths (
				component_purl text,
				root uuid,
				path uuid[]
			);`)
	if err != nil {
		return fmt.Errorf("could not create table for vuln paths: %w", err)
	}

	group := &errgroup.Group{}
	resultsChannel := make(chan purlPathResult)
	vulnPathColumns := []string{"component_purl", "root", "path"}

	group.Go(func() error {
		_, err := runner.ScanAffectedPurls(ctx, scanTx, resultsChannel, utils.Map(affectedPurls, func(pac purlAffectedComponent) string { return pac.purl }))
		return err
	})

	var groupErr error
	go func() {
		groupErr = group.Wait()
		close(resultsChannel)
	}()

	const batchSize = 5000
	rowsBuffer := make([]vulnPath, 0, batchSize*1.25) // 75% pctfree
	copyRows := func() error {
		_, err := scanTx.CopyFrom(ctx, pgx.Identifier{"vuln_paths"}, vulnPathColumns, pgx.CopyFromSlice(len(rowsBuffer), func(i int) ([]any, error) {
			return []any{rowsBuffer[i].Purl, rowsBuffer[i].Root, rowsBuffer[i].Path}, nil
		}))
		rowsBuffer = rowsBuffer[:0]
		return err
	}
	for result := range resultsChannel {
		purl := canonicalPurl(result.Purl, purlMemo)
		for _, root := range result.ExplodedRoots {
			rowsBuffer = append(rowsBuffer, vulnPath{
				Purl: purl,
				Path: nil,
				Root: root,
			})
		}

		for _, path := range result.Paths {
			rowsBuffer = append(rowsBuffer, vulnPath{
				Purl: purl,
				Path: toStoredPath(path),
				Root: path[len(path)-1],
			})
		}

		if len(rowsBuffer) >= batchSize {
			slog.Info("streaming batch to database", "amount", len(rowsBuffer))
			if err := copyRows(); err != nil {
				return fmt.Errorf("could not copy vuln paths into table: %w", err)
			}
		}
	}

	if groupErr != nil {
		return fmt.Errorf("could not scan purl batch: %w", groupErr)
	}

	// copy the remaining rows as well
	if len(rowsBuffer) > 0 {
		if err := copyRows(); err != nil {
			return fmt.Errorf("could not copy vuln paths into table: %w", err)
		}
	}

	slog.Info("finished scanning all purls", "time", time.Since(start))

	start = time.Now()
	// now materialize the new dependency vulns from the scan data
	_, err = scanTx.Exec(ctx, `
		CREATE TABLE public.new_dependency_vulns AS (
			SELECT 
				vp.component_purl, vp.path,
				pm.fixed_version,cves.cve as cve_id, 
				s.asset_id, s.asset_version_name, s.artifact_name , s.source
			FROM vuln_paths vp
			JOIN sboms s 
				ON s.root_subtree_hash = vp.root
			JOIN purl_mapping pm
				ON pm.purl = vp.component_purl
			JOIN cves
				ON cves.id = pm.cve_id
		);`)
	if err != nil {
		return fmt.Errorf("could not materialize new dependency vulns: %w", err)
	}

	// speed up artifact lookup queries
	_, err = scanTx.Exec(ctx, `CREATE INDEX artifact_lookup_idx ON public.new_dependency_vulns (asset_id, asset_version_name, artifact_name);`)
	if err != nil {
		return fmt.Errorf("could not create index on new_dependency_vulns artifact lookup: %w", err)
	}

	// speed up artifact lookup queries on sboms
	_, err = scanTx.Exec(ctx, `CREATE INDEX IF NOT EXISTS artifact_lookup_idx ON public.sboms (asset_id, asset_version_name, artifact_name);`)
	if err != nil {
		return fmt.Errorf("could not create index on sboms artifact lookup: %w", err)
	}

	err = scanTx.Commit(ctx)
	if err != nil {
		panic(err)
	}

	slog.Info("finished materializing new dependency vulns", "time", time.Since(start))

	startHandling := time.Now()

	// get all assets which actually need processing
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT asset_id FROM dependency_vulns
		UNION 
		SELECT DISTINCT asset_id FROM new_dependency_vulns;`)
	if err != nil {
		return err
	}
	defer rows.Close()

	assetIDs := make([]uuid.UUID, 0, 500)
	var id uuid.UUID
	for rows.Next() {
		err = rows.Scan(&id)
		if err != nil {
			return fmt.Errorf("could not scan asset id from query: %w", err)
		}
		assetIDs = append(assetIDs, id)
	}
	rows.Close()

	slog.Info("start handling scan results for assets", "number of assets", len(assetIDs))
	start = time.Now()
	cache := newScanRunCache()
	for i, assetID := range assetIDs {
		err = runner.handleScanResultForAsset(ctx, sbomSnapshot, conn, assetID, cache)
		if err != nil {
			slog.Error("could not handle scan result for asset", "err", err, "asset", assetID)
		} else if (i+1)%10 == 0 {
			slog.Info(fmt.Sprintf("finished asset %d/%d", i+1, len(assetIDs)), "batchTime", time.Since(start))
			start = time.Now()
		}
	}
	slog.Info("finished all handle scan results", "time", time.Since(startHandling))

	return nil
}

type vulnPath struct {
	Purl string
	Root uuid.UUID
	Path []uuid.UUID
}

// convert BFS result (purl to root) to dependency vuln path (first non root to purl)
func toStoredPath(path []uuid.UUID) []uuid.UUID {
	stored := make([]uuid.UUID, 0, len(path)-1)
	for i := len(path) - 2; i >= 0; i-- {
		stored = append(stored, path[i])
	}
	return stored
}

// convert to canonical purl to ensure consistency with scan function
func canonicalPurl(raw string, memo map[string]string) string {
	if canonical, ok := memo[raw]; ok {
		return canonical
	}

	canonical := raw
	if parsed, err := packageurl.FromString(raw); err == nil {
		if unescaped, err := normalize.PURLToString(parsed); err == nil {
			canonical = unescaped
		}
	}

	memo[raw] = canonical
	return canonical
}

// cache common lookups between assets
type scanRunCache struct {
	cves     map[string]*models.CVE
	projects map[uuid.UUID]models.Project
	orgs     map[uuid.UUID]models.Org
}

func newScanRunCache() *scanRunCache {
	return &scanRunCache{
		cves:     make(map[string]*models.CVE, 15_000),
		projects: make(map[uuid.UUID]models.Project),
		orgs:     make(map[uuid.UUID]models.Org),
	}
}

// cves need to be fetched in addition so we can calculate the risk
func (runner *DaemonRunner) hydrateCVEs(ctx context.Context, vulns []models.DependencyVuln, cache map[string]*models.CVE) error {
	missing := make([]string, 0)
	for i := range vulns {
		if _, ok := cache[vulns[i].CVEID]; !ok {
			// a cve the vulndb does not know stays nil, so it is looked up only once
			cache[vulns[i].CVEID] = nil
			missing = append(missing, vulns[i].CVEID)
		}
	}

	if len(missing) > 0 {
		cves, err := runner.cveRepository.FindCVEs(ctx, nil, missing)
		if err != nil {
			return err
		}
		// FindCVEs matches case insensitively, so the ids are mapped back the same way
		found := make(map[string]*models.CVE, len(cves))
		for i := range cves {
			found[strings.ToLower(cves[i].CVE)] = &cves[i]
		}
		for _, id := range missing {
			if cve, ok := found[strings.ToLower(id)]; ok {
				cache[id] = cve
			}
		}
	}

	for i := range vulns {
		if cve := cache[vulns[i].CVEID]; cve != nil {
			vulns[i].CVE = cve
		}
	}
	return nil
}

func (runner *DaemonRunner) handleScanResultForAsset(ctx context.Context, sbomSnapshot map[uuid.UUID][]uuid.UUID, conn *pgxpool.Conn, assetID uuid.UUID, cache *scanRunCache) error {
	assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(ctx, nil, assetID)
	if err != nil {
		return fmt.Errorf("could not fetch asset versions for asset: %w", err)
	}

	var asset models.Asset
	err = runner.db.Raw(`SELECT * FROM assets WHERE id = ?`, assetID).Find(&asset).Error
	if err != nil {
		return fmt.Errorf("could not fetch asset details: %w", err)
	}

	// a failing asset version is rolled back on its own and must not block the others
	errs := make([]error, 0)
	for _, assetVersion := range assetVersions {
		if err := runner.handleScanResultForAssetVersion(ctx, conn, sbomSnapshot, asset, assetVersion, cache); err != nil {
			errs = append(errs, fmt.Errorf("asset version %s: %w", assetVersion.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (runner *DaemonRunner) handleScanResultForAssetVersion(ctx context.Context, conn *pgxpool.Conn, sbomSnapshot map[uuid.UUID][]uuid.UUID, asset models.Asset, assetVersion models.AssetVersion, cache *scanRunCache) error {
	filterStaleArtifacts := func(assetVersion models.AssetVersion, tx pgx.Tx) []models.Artifact {
		artifacts := assetVersion.Artifacts
		if len(artifacts) == 0 {
			return []models.Artifact{}
		}

		freshArtifacts := make([]models.Artifact, 0, len(artifacts))

		rootRows, err := tx.Query(ctx, `
		SELECT artifact_name, root_subtree_hash 
		FROM sboms s
		WHERE s.asset_version_name = $1
		AND s.asset_id = $2;`, assetVersion.Name, assetVersion.AssetID)
		if err != nil {
			return freshArtifacts
		}
		defer rootRows.Close()

		type mapKey struct {
			ArtifactHash uuid.UUID
			ArtifactName string
		}

		var root uuid.UUID
		var artifact string
		currentState := make(map[mapKey][]uuid.UUID, len(artifacts))
		for rootRows.Next() {
			err = rootRows.Scan(&artifact, &root)
			if err != nil {
				return freshArtifacts
			}
			artifactHash := md5.Sum([]byte(artifact + assetVersion.Name + assetVersion.AssetID.String()))
			currentState[mapKey{ArtifactHash: artifactHash, ArtifactName: artifact}] = append(currentState[mapKey{ArtifactHash: artifactHash, ArtifactName: artifact}], root)
		}
		rootRows.Close()
		if err := rootRows.Err(); err != nil {
			return freshArtifacts
		}

	artifactLoop:
		for artifactKey, currentRoots := range currentState {

			snapshotRoots, ok := sbomSnapshot[artifactKey.ArtifactHash]
			if !ok {
				// artifact did not exist before so data is stale
				continue
			}

			// check if all current sboms already existed
			for _, current := range currentRoots {
				if !slices.Contains(snapshotRoots, current) {
					continue artifactLoop
				}
			}

			// and vice versa
			for _, snapshot := range snapshotRoots {
				if !slices.Contains(currentRoots, snapshot) {
					continue artifactLoop
				}
			}
			freshArtifacts = append(freshArtifacts, models.Artifact{
				ArtifactName:     artifactKey.ArtifactName,
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
			})
		}
		return freshArtifacts
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	artifacts := filterStaleArtifacts(assetVersion, tx)
	if len(artifacts) == 0 {
		slog.Warn("no artifacts survived the filter", "asset version", assetVersion.Name, "assetID", assetVersion.AssetID)
		return nil
	}

	existing, err := runner.dependencyVulnRepository.ListByAssetAndAssetVersionWithoutEvents(ctx, nil, assetVersion.Name, asset.ID)
	if err != nil {
		return fmt.Errorf("could not get existing dependency vulns: %w", err)
	}

	opened := make(map[string][]models.DependencyVuln, len(artifacts))
	for _, artifact := range artifacts {
		// a savepoint per artifact: a failing artifact is undone without aborting the asset version transaction
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return fmt.Errorf("could not create savepoint for artifact %s: %w", artifact.ArtifactName, err)
		}
		next, artifactOpened, err := runner.handleArtifact(ctx, savepoint, artifact, existing, asset, cache)
		if err != nil {
			slog.Error("could not handle scan results", "err", err, "artifact", artifact.ArtifactName, "assetVersion", assetVersion.Name)
			if err := savepoint.Rollback(ctx); err != nil {
				return fmt.Errorf("could not roll back savepoint for artifact %s: %w", artifact.ArtifactName, err)
			}
			continue // existing keeps the state from before this artifact
		}
		if err := savepoint.Commit(ctx); err != nil {
			return fmt.Errorf("could not release savepoint for artifact %s: %w", artifact.ArtifactName, err)
		}
		existing = next
		opened[artifact.ArtifactName] = artifactOpened
	}

	// dry runs are rolled back by the deferred rollback
	if runner.debugOptions.DryRun {
		slog.Info("[DRY-RUN] rolled back scan results", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID, "artifacts", len(artifacts))
	} else if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit scan results: %w", err)
	}

	// only notify after the commit, otherwise subscribers could be told about vulns that were rolled back
	for artifactName, vulns := range opened {
		runner.notifyDependencyVulnsDetected(ctx, cache, asset, assetVersion, artifactName, vulns)
	}
	return nil
}

// handleArtifact must run inside its own savepoint, a failure leaves the transaction aborted until it is rolled back
func (runner *DaemonRunner) handleArtifact(ctx context.Context, tx pgx.Tx, artifact models.Artifact, existingDependencyVulns []models.DependencyVuln, asset models.Asset, cache *scanRunCache) (snapshot []models.DependencyVuln, opened []models.DependencyVuln, err error) {
	foundVulns, err := runner.FetchNewVulnsForArtifact(ctx, tx, artifact)
	if err != nil {
		return nil, nil, fmt.Errorf("could not query found vulns for artifact: %w", err)
	}

	if err := runner.hydrateCVEs(ctx, foundVulns, cache.cves); err != nil {
		return nil, nil, fmt.Errorf("could not load cve details for artifact: %w", err)
	}

	return runner.HandleScanResultBatch(ctx, tx, foundVulns, existingDependencyVulns, artifact.ArtifactName, artifact.AssetVersionName, asset)
}

// returns the new state so the other artifacts do not operate on stale data
func (runner *DaemonRunner) HandleScanResultBatch(ctx context.Context, tx pgx.Tx, dependencyVulns, existingDependencyVulns []models.DependencyVuln, artifactName, assetVersionName string, asset models.Asset) (snapshot []models.DependencyVuln, opened []models.DependencyVuln, err error) {
	diff := statemachine.DiffScanResults(artifactName, dependencyVulns, existingDependencyVulns)

	// only newly discovered vulns are matched against other branches, so restrict the query to their signatures
	newlyDiscoveredSignatures := make([]int64, len(diff.NewlyDiscovered))
	for i := range diff.NewlyDiscovered {
		newlyDiscoveredSignatures[i] = utils.HashToInt64(diff.NewlyDiscovered[i].CalculateAssetVersionIndependentHash())
	}

	existingVulnsOnOtherBranch, err := runner.dependencyVulnRepository.GetDependencyVulnsByOtherAssetVersions(ctx, nil, assetVersionName, asset.ID, newlyDiscoveredSignatures)
	if err != nil {
		slog.Error("could not get existing dependencyVulns on default branch", "err", err)
		return nil, nil, err
	}

	// remove from fixed vulns and fixed on this artifact name all vulns, that have more than a single path to them
	// this means, that another source is still saying, its part of this artifact
	unfixablePurls, err := fetchPurlsInMultipleSBOMs(ctx, tx, asset.ID, assetVersionName, artifactName)
	if err != nil {
		return nil, nil, fmt.Errorf("could not fetch purls in multiple sboms: %w", err)
	}
	filterPredicate := func(dv models.DependencyVuln) bool {
		_, ok := unfixablePurls[dv.ComponentPurl]
		return !ok
	}

	fixedOnThisArtifactName := utils.Filter(diff.RemovedFromArtifact, filterPredicate)

	branchDiff := statemachine.DiffVulnsBetweenBranches(utils.Map(diff.NewlyDiscovered, utils.Ptr), utils.Map(existingVulnsOnOtherBranch, utils.Ptr))

	// make sure to first create a user detected event for vulnerabilities with just upstream events
	// this way we preserve the event history
	if err := runner.DetectedExistingVulnOnDifferentBranch(ctx, tx, artifactName, branchDiff.ExistingOnOtherBranches, asset); err != nil {
		slog.Error("error when trying to add events for existing vulnerability on different branch")
		return nil, nil, err
	}
	// We can create the newly found one without checking anything
	if err := runner.DetectedDependencyVulns(ctx, tx, "system", nil, artifactName, utils.DereferenceSlice(branchDiff.NewToAllBranches), asset); err != nil {
		return nil, nil, err
	}

	err = runner.DetectedDependencyVulnInAnotherArtifact(ctx, tx, diff.NewInArtifact, artifactName)
	if err != nil {
		slog.Error("error when trying to associate new artifact to vulnerabilities")
		return nil, nil, err
	}

	err = runner.DidNotDetectDependencyVulnInArtifactAnymore(ctx, tx, fixedOnThisArtifactName, artifactName)
	if err != nil {
		slog.Error("error when trying to remove artifact association from vulnerabilities")
		return nil, nil, err
	}

	created := append(utils.DereferenceSlice(branchDiff.NewToAllBranches), utils.Map(branchDiff.ExistingOnOtherBranches, func(match statemachine.BranchVulnMatch[*models.DependencyVuln]) models.DependencyVuln {
		return *match.CurrentBranchVuln
	})...)

	return applyBatchToSnapshot(existingDependencyVulns, created, diff.NewInArtifact, fixedOnThisArtifactName, artifactName), created, nil
}

func (runner *DaemonRunner) notifyDependencyVulnsDetected(ctx context.Context, cache *scanRunCache, asset models.Asset, assetVersion models.AssetVersion, artifactName string, opened []models.DependencyVuln) {
	if len(opened) == 0 || !(assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag) {
		return
	}

	// make sure to swallow if wrapper doesn't work
	if runner.debugOptions.DryRun {
		slog.Info("[DRY-RUN] would dispatch dependency vulns detected event", "artifact", artifactName, "amount", len(opened))
		return
	}

	project, org, err := runner.projectAndOrgFor(ctx, cache, asset)
	if err != nil {
		slog.Error("could not load project and org for detected event", "err", err, "assetID", asset.ID)
		return
	}

	// dispatched synchronously: a detached goroutine can outlive the daemon run
	if err := runner.integrationAggregate.HandleEvent(ctx, shared.DependencyVulnsDetectedEvent{
		AssetVersion: shared.ToAssetVersionObject(assetVersion),
		Asset:        shared.ToAssetObject(asset),
		Project:      shared.ToProjectObject(project),
		Org:          shared.ToOrgObject(org),
		Vulns:        utils.Map(opened, transformer.DependencyVulnToDTO),
		Artifact: shared.ArtifactObject{
			ArtifactName: artifactName,
		},
	}, nil); err != nil {
		slog.Error("could not handle dependency vulnerabilities detected event", "err", err, "artifact", artifactName)
	}
}

// try to get project and org from cache, otherwise read from db
func (runner *DaemonRunner) projectAndOrgFor(ctx context.Context, cache *scanRunCache, asset models.Asset) (models.Project, models.Org, error) {
	project, ok := cache.projects[asset.ProjectID]
	if !ok {
		var err error
		project, err = runner.projectRepository.Read(ctx, nil, asset.ProjectID)
		if err != nil {
			return models.Project{}, models.Org{}, err
		}
		cache.projects[asset.ProjectID] = project
	}

	org, ok := cache.orgs[project.OrganizationID]
	if !ok {
		var err error
		org, err = runner.orgRepository.GetOrgByID(ctx, nil, project.OrganizationID)
		if err != nil {
			return models.Project{}, models.Org{}, err
		}
		cache.orgs[project.OrganizationID] = org
	}

	return project, org, nil
}

// applyBatchToSnapshot mirrors the writes of one artifact onto the in memory snapshot
func applyBatchToSnapshot(snapshot, created, addedToArtifact, removedFromArtifact []models.DependencyVuln, artifactName string) []models.DependencyVuln {
	added := vulnIDSet(addedToArtifact)
	removed := vulnIDSet(removedFromArtifact)
	if len(added) == 0 && len(removed) == 0 {
		return append(snapshot, created...)
	}

	for i := range snapshot {
		id := snapshot[i].CalculateHash()
		if _, ok := added[id]; ok {
			snapshot[i].Artifacts = append(snapshot[i].Artifacts, models.Artifact{
				ArtifactName:     artifactName,
				AssetVersionName: snapshot[i].AssetVersionName,
				AssetID:          snapshot[i].AssetID,
			})
		}
		if _, ok := removed[id]; ok {
			snapshot[i].Artifacts = slices.DeleteFunc(snapshot[i].Artifacts, func(artifact models.Artifact) bool {
				return artifact.ArtifactName == artifactName
			})
		}
	}

	return append(snapshot, created...)
}

func vulnIDSet(vulns []models.DependencyVuln) map[uuid.UUID]struct{} {
	ids := make(map[uuid.UUID]struct{}, len(vulns))
	for i := range vulns {
		ids[vulns[i].CalculateHash()] = struct{}{}
	}
	return ids
}

func (runner *DaemonRunner) DetectedExistingVulnOnDifferentBranch(ctx context.Context, tx pgx.Tx, scannerID string, dependencyVulns []statemachine.BranchVulnMatch[*models.DependencyVuln], asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	vulns := utils.Map(dependencyVulns, func(el statemachine.BranchVulnMatch[*models.DependencyVuln]) models.DependencyVuln {
		return *el.CurrentBranchVuln
	})
	events := utils.Flat(utils.Map(dependencyVulns, func(el statemachine.BranchVulnMatch[*models.DependencyVuln]) []models.VulnEvent {
		return el.EventsToCopy
	}))

	if err := copyDependencyVulns(ctx, tx, vulns); err != nil {
		return err
	}
	return copyVulnEvents(ctx, tx, events)
}

func (runner *DaemonRunner) DetectedDependencyVulns(ctx context.Context, tx pgx.Tx, userID string, userAgent *string, artifactName string, dependencyVulns []models.DependencyVuln, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(dependencyVulns))
	for i := range dependencyVulns {
		depth := max(len(dependencyVulns[i].VulnerabilityPath), 1)
		riskReport := vulndb.RawRisk(dependencyVulns[i].CVE, asset.Environmental, depth)
		events[i] = models.NewDetectedEvent(dependencyVulns[i].CalculateHash(), dtos.VulnTypeDependencyVuln, userID, false, userAgent)
		dependencyVulns[i].SetRawRiskAssessment(riskReport.Risk)
		dependencyVulns[i].RiskRecalculatedAt = time.Now()
		statemachine.Apply(&dependencyVulns[i], events[i])
	}

	if err := copyDependencyVulns(ctx, tx, dependencyVulns); err != nil {
		return err
	}
	return copyVulnEvents(ctx, tx, events)
}

// copyDependencyVulns inserts new vulns and their artifact associations, COPY fails on already existing vulns
func copyDependencyVulns(ctx context.Context, tx pgx.Tx, vulns []models.DependencyVuln) error {
	now := time.Now()
	artifactRows := make([][]any, 0, len(vulns))

	for i := range vulns {
		vuln := &vulns[i]
		// gorm used to call this hook on save, it sets the id and signatures
		if err := vuln.BeforeSave(nil); err != nil {
			return err
		}
		// column defaults gorm used for zero values
		if vuln.State == "" {
			vuln.State = dtos.VulnStateOpen
		}
		if vuln.LastStateChange.IsZero() {
			vuln.LastStateChange = now
		}
		// a nil path would be stored as json null instead of []
		if vuln.VulnerabilityPath == nil {
			vuln.VulnerabilityPath = []string{}
		}
		vuln.CreatedAt = now
		vuln.UpdatedAt = now

		for _, artifact := range vuln.Artifacts {
			artifactRows = append(artifactRows, []any{artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID, vuln.ID})
		}
	}

	_, err := tx.CopyFrom(ctx, pgx.Identifier{"dependency_vulns"}, []string{"id", "asset_version_name", "asset_id", "state", "last_state_change", "created_at", "updated_at", "cve_id", "component_purl", "component_fixed_version", "direct_dependency_fixed_version", "vulnerability_path", "risk_assessment", "risk_recalculated_at", "signature", "asset_signature"}, pgx.CopyFromSlice(len(vulns), func(i int) ([]any, error) {
		v := vulns[i]
		return []any{v.ID, v.AssetVersionName, v.AssetID, string(v.State), v.LastStateChange, v.CreatedAt, v.UpdatedAt, v.CVEID, v.ComponentPurl, v.ComponentFixedVersion, v.DirectDependencyFixedVersion, v.VulnerabilityPath, v.RiskAssessment, v.RiskRecalculatedAt, v.Signature, v.AssetSignature}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy dependency vulns: %w", err)
	}

	_, err = tx.CopyFrom(ctx, pgx.Identifier{"artifact_dependency_vulns"}, []string{"artifact_artifact_name", "artifact_asset_version_name", "artifact_asset_id", "dependency_vuln_id"}, pgx.CopyFromRows(artifactRows))
	if err != nil {
		return fmt.Errorf("could not copy artifact associations: %w", err)
	}
	return nil
}

func copyVulnEvents(ctx context.Context, tx pgx.Tx, events []models.VulnEvent) error {
	now := time.Now()
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_events"}, []string{"created_at", "type", "user_id", "justification", "mechanical_justification", "original_asset_version_name", "created_by_vex_rule", "dependency_vuln_id", "user_agent", "vex_rule_id", "asset_signature"}, pgx.CopyFromSlice(len(events), func(i int) ([]any, error) {
		ev := events[i]
		// events copied from other branches keep their original timestamp
		createdAt := ev.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		return []any{createdAt, string(ev.Type), ev.UserID, ev.Justification, string(ev.MechanicalJustification), ev.OriginalAssetVersionName, ev.CreatedByVexRule, ev.DependencyVulnID, ev.UserAgent, ev.VexRuleID, ev.AssetSignature}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy vuln events: %w", err)
	}
	return nil
}

func (runner *DaemonRunner) DetectedDependencyVulnInAnotherArtifact(ctx context.Context, tx pgx.Tx, vulnerabilities []models.DependencyVuln, artifactName string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	assetVersionNames := make([]string, 0, len(vulnerabilities))
	assetIDs := make([]uuid.UUID, 0, len(vulnerabilities))
	dependencyVulnIDs := make([]uuid.UUID, 0, len(vulnerabilities))

	for i := range vulnerabilities {
		alreadyAssociated := false
		for _, a := range vulnerabilities[i].Artifacts {
			if a.ArtifactName == artifactName {
				alreadyAssociated = true
				break
			}
		}
		if !alreadyAssociated {
			assetVersionNames = append(assetVersionNames, vulnerabilities[i].AssetVersionName)
			assetIDs = append(assetIDs, vulnerabilities[i].AssetID)
			dependencyVulnIDs = append(dependencyVulnIDs, vulnerabilities[i].CalculateHash())
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO artifact_dependency_vulns 
				(artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, dependency_vuln_id)
				SELECT 
					$1,
					UNNEST($2::text[]),
					UNNEST($3::uuid[]),
					UNNEST($4::uuid[])
				ON CONFLICT DO NOTHING;`, artifactName, assetVersionNames, assetIDs, dependencyVulnIDs)

	return err
}

func (runner *DaemonRunner) DidNotDetectDependencyVulnInArtifactAnymore(ctx context.Context, tx pgx.Tx, vulnerabilities []models.DependencyVuln, artifactName string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	assetVersionNames := make([]string, len(vulnerabilities))
	assetIDs := make([]uuid.UUID, len(vulnerabilities))
	dependencyVulnIDs := make([]uuid.UUID, len(vulnerabilities))
	for i := range vulnerabilities {
		assetVersionNames[i] = vulnerabilities[i].AssetVersionName
		assetIDs[i] = vulnerabilities[i].AssetID
		dependencyVulnIDs[i] = vulnerabilities[i].CalculateHash()
	}

	_, err := tx.Exec(ctx, `DELETE FROM artifact_dependency_vulns adv
				USING UNNEST($2::text[], $3::uuid[], $4::uuid[]) AS u(asset_version_name, asset_id, dependency_vuln_id)
				WHERE adv.artifact_artifact_name = $1
				AND adv.artifact_asset_version_name = u.asset_version_name
				AND adv.artifact_asset_id = u.asset_id
				AND adv.dependency_vuln_id = u.dependency_vuln_id;`, artifactName, assetVersionNames, assetIDs, dependencyVulnIDs)

	return err
}

func (runner *DaemonRunner) FetchNewVulnsForArtifact(ctx context.Context, tx pgx.Tx, artifact models.Artifact) ([]models.DependencyVuln, error) {
	// the vuln id only hashes cve and path, so rows differing only in fixed_version (multiple affected components) must collapse into one vuln
	rows, err := tx.Query(ctx, `
	SELECT DISTINCT ON (vp.cve_id, path_purls)
    vp.component_purl,
    ARRAY(
        SELECT nodes.component_id
        FROM UNNEST(vp.path) WITH ORDINALITY AS u(node_hash, ord)
        JOIN sbom_merkle_nodes nodes
        ON nodes.node_hash = u.node_hash
        ORDER BY u.ord
    ) AS path_purls,
    vp.cve_id,
    vp.fixed_version
	FROM new_dependency_vulns vp
	WHERE vp.asset_id = $1
	AND vp.asset_version_name = $2
	AND vp.artifact_name = $3
	ORDER BY vp.cve_id, path_purls, vp.fixed_version NULLS LAST;`, artifact.AssetID, artifact.AssetVersionName, artifact.ArtifactName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dependencyVulns := make([]models.DependencyVuln, 0, 1000)
	var vuln models.DependencyVuln
	for rows.Next() {
		err = rows.Scan(&vuln.ComponentPurl, &vuln.VulnerabilityPath, &vuln.CVEID, &vuln.ComponentFixedVersion)
		if err != nil {
			return nil, err
		}
		vuln.CVE = &models.CVE{CVE: vuln.CVEID}
		vuln.Artifacts = []models.Artifact{artifact}
		vuln.AssetID = artifact.AssetID
		vuln.AssetVersionName = artifact.AssetVersionName
		dependencyVulns = append(dependencyVulns, vuln)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func fetchPurlsInMultipleSBOMs(ctx context.Context, tx pgx.Tx, assetID uuid.UUID, assetVersionName, artifactName string) (map[string]struct{}, error) {
	rows, err := tx.Query(ctx, `
	SELECT component_purl
	FROM new_dependency_vulns
	WHERE asset_id = $1
	AND asset_version_name = $2
	AND artifact_name = $3
	GROUP BY component_purl
	HAVING COUNT(DISTINCT source) > 1;`, assetID, assetVersionName, artifactName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	purls := make(map[string]struct{})
	var purl string
	for rows.Next() {
		err = rows.Scan(&purl)
		if err != nil {
			return nil, err
		}
		purls[purl] = struct{}{}
	}
	return purls, rows.Err()
}

type purlPathResult struct {
	Purl  string
	Paths [][]uuid.UUID // vulnerable node -> ... -> sbom root
	// sboms reached by more than maxPathsPerRoot paths, none of their paths are kept
	ExplodedRoots []uuid.UUID
}

func (runner *DaemonRunner) ScanAffectedPurls(ctx context.Context, tx pgx.Tx, results chan purlPathResult, purls []string) (map[string][][]uuid.UUID, error) {
	start := time.Now()
	// calculate map size upper bound
	row := tx.QueryRow(ctx, `SELECT COUNT(*) FROM sbom_merkle_nodes;`)

	var count int
	err := row.Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("could not query count of nodes: %w", err)
	}

	// leaf rows carry a NULL child and are no edges
	edgeRows, err := tx.Query(ctx, `SELECT subtree_hash,direct_dependency_subtree_hash FROM sbom_merkle_edges WHERE direct_dependency_subtree_hash IS NOT NULL;`)
	if err != nil {
		return nil, fmt.Errorf("could not query paths for purls: %w", err)
	}
	defer edgeRows.Close()

	// nodes are mapped to dense ids so the traversal indexes slices instead of hashing uuids
	nodeIDs := make(map[uuid.UUID]int32, count)
	nodeHashes := make([]uuid.UUID, 0, count)
	parents := make([][]int32, 0, count)
	toNodeID := func(hash uuid.UUID) int32 {
		id, ok := nodeIDs[hash]
		if !ok {
			id = int32(len(nodeHashes))
			nodeIDs[hash] = id
			nodeHashes = append(nodeHashes, hash)
			parents = append(parents, nil)
		}
		return id
	}

	var parent, child uuid.UUID
	for edgeRows.Next() {
		err = edgeRows.Scan(&parent, &child)
		if err != nil {
			return nil, fmt.Errorf("could not scan edge: %w", err)
		}
		childID := toNodeID(child)
		parentID := toNodeID(parent)
		parents[childID] = append(parents[childID], parentID)
	}
	edgeRows.Close()
	if err := edgeRows.Err(); err != nil {
		return nil, fmt.Errorf("could not scan rows: %w", err)
	}

	// order by hash so the traversal and the chosen paths do not depend on the row order of the queries
	compareNodes := func(a, b int32) int {
		return bytes.Compare(nodeHashes[a][:], nodeHashes[b][:])
	}
	for i := range parents {
		slices.SortFunc(parents[i], compareNodes)
	}

	slog.Info("loaded SBOM into memory", "time", time.Since(start))

	purlRows, err := tx.Query(ctx, `
		SELECT node_hash, component_id 
		FROM sbom_merkle_nodes
		WHERE component_id = ANY($1)`, purls)
	if err != nil {
		return nil, fmt.Errorf("could not fetch hash to purl mapping: %w", err)
	}
	defer purlRows.Close()

	// a purl has one node per distinct subtree, so it can map to multiple nodes
	purlToNodes := make(map[string][]int32, len(purls))
	var purl string
	var hash uuid.UUID
	for purlRows.Next() {
		err = purlRows.Scan(&hash, &purl)
		if err != nil {
			return nil, fmt.Errorf("could not scan purl row: %w", err)
		}
		// a node without edges can never reach a root
		if id, ok := nodeIDs[hash]; ok {
			purlToNodes[purl] = append(purlToNodes[purl], id)
		}
	}
	purlRows.Close()
	if err := purlRows.Err(); err != nil {
		return nil, fmt.Errorf("could not scan purl rows: %w", err)
	}
	for _, nodes := range purlToNodes {
		slices.SortFunc(nodes, compareNodes)
	}

	// lookup which nodes are root nodes
	rootRows, err := tx.Query(ctx, `
		SELECT node_hash
		FROM sbom_merkle_nodes nodes 
		WHERE EXISTS (
			SELECT FROM sboms s 
			WHERE s.root_subtree_hash = nodes.node_hash
		);`)
	if err != nil {
		return nil, fmt.Errorf("could not query root nodes: %w", err)
	}
	defer rootRows.Close()

	var rootHash uuid.UUID
	isNodeRoot := make([]bool, len(nodeHashes))
	for rootRows.Next() {
		err = rootRows.Scan(&rootHash)
		if err != nil {
			return nil, fmt.Errorf("could not scan root row: %w", err)
		}
		// roots outside the edge graph can never be reached
		if id, ok := nodeIDs[rootHash]; ok {
			isNodeRoot[id] = true
		}
	}
	rootRows.Close()
	err = rootRows.Err()
	if err != nil {
		return nil, fmt.Errorf("ran into error when reading root rows: %w", err)
	}

	const maxQueueLength = 4000
	queue := NewDynamicQueue[[]int32](maxQueueLength) // queue of paths
	toHashes := func(path []int32) []uuid.UUID {
		hashes := make([]uuid.UUID, len(path))
		for i, id := range path {
			hashes[i] = nodeHashes[id]
		}
		return hashes
	}

	for _, vulnerablePurl := range purls {
		// paths stay ids until the purl is done, a root can still explode later on
		pathsPerRoot := make(map[int32][][]int32)
		explodedRoots := make(map[int32]struct{})
		// seed with the vulnerable node itself so its direct parents get the root check as well
		for _, nodeID := range purlToNodes[vulnerablePurl] {
			queue.Append([]int32{nodeID})
		}

		for {
			next, ok := queue.Next()
			if !ok {
				// queue is empty continue with the next purl
				break
			}

			for _, node := range parents[next[len(next)-1]] {
				hasParents := len(parents[node]) > 0
				recordable := false
				if isNodeRoot[node] {
					_, exploded := explodedRoots[node]
					recordable = !exploded
				}
				if !recordable && !hasParents {
					continue
				}

				// each path needs its own backing array otherwise siblings overwrite each other's last node
				newPath := make([]int32, len(next), len(next)+1)
				copy(newPath, next)
				newPath = append(newPath, node)

				// paths are vulnerable node -> ... -> root, the root is kept so the path can be mapped to its sboms
				if recordable {

					if len(pathsPerRoot[node]) >= maxPathsPerRoot {
						// path explosion, none of the paths into this sbom are kept
						delete(pathsPerRoot, node)
						explodedRoots[node] = struct{}{}
					} else {
						// paths are never modified after creation, so sharing newPath with the queue is safe
						pathsPerRoot[node] = append(pathsPerRoot[node], newPath)
					}
				}
				// a root can also be a subtree of another sbom, so only stop where there are no more parents
				if hasParents {
					queue.Append(newPath)
				}
			}
		}
		queue.Reset()

		// map iteration is random, sorting the roots by hash keeps the output order stable
		result := purlPathResult{Purl: vulnerablePurl}
		for _, root := range slices.SortedFunc(maps.Keys(pathsPerRoot), compareNodes) {
			for _, path := range pathsPerRoot[root] {
				result.Paths = append(result.Paths, toHashes(path))
			}
		}
		for _, root := range slices.SortedFunc(maps.Keys(explodedRoots), compareNodes) {
			result.ExplodedRoots = append(result.ExplodedRoots, nodeHashes[root])
		}
		results <- result
	}

	return nil, nil
}

const maxPathsPerRoot = 11

type dynamicQueue[T any] struct {
	MaxSize        int
	Queue          []T
	CurrentElement int
}

func NewDynamicQueue[T any](maxSize int) *dynamicQueue[T] {
	return &dynamicQueue[T]{
		MaxSize:        maxSize,
		Queue:          make([]T, 0, maxSize),
		CurrentElement: 0,
	}
}

func (queue *dynamicQueue[T]) Next() (next T, ok bool) {
	if queue.CurrentElement >= len(queue.Queue) {
		return next, false
	}
	next = queue.Queue[queue.CurrentElement]
	queue.CurrentElement++
	queue.shrink()
	return next, true
}

func (queue *dynamicQueue[T]) Append(element T) {
	if len(queue.Queue) == queue.MaxSize {
		slog.Warn("queue overflow")
	}
	queue.Queue = append(queue.Queue, element)
}

func (queue *dynamicQueue[T]) Reset() {
	clear(queue.Queue)
	queue.Queue = queue.Queue[:0]
	queue.CurrentElement = 0
}

func (queue *dynamicQueue[T]) shrink() {
	// compacting before half of the slice is consumed copies large queues over and over
	if queue.CurrentElement <= queue.MaxSize/2 || queue.CurrentElement < len(queue.Queue)/2 {
		return
	}
	// move the unread elements to the front and drop references to consumed ones so the GC can free them
	remaining := copy(queue.Queue, queue.Queue[queue.CurrentElement:])
	clear(queue.Queue[remaining:])
	queue.Queue = queue.Queue[:remaining]
	queue.CurrentElement = 0
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
			if !runner.stageEnabled("ScanAsset") {
				out <- assetWithDetails
				continue
			}
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org
			slog.Info("start scanning asset versions", "amount", len(assetVersions))
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.scan")
			errs := make([]error, 0)
			for i := range assetVersions {
				start := time.Now()
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					// each artifact's SBOMs are loaded on their own - there is no
					// shared asset-version graph to scope out of any more
					bom, err := runner.assetVersionService.LoadArtifactSBOMs(stageCtx, nil, assetVersions[i], artifact.ArtifactName)
					if err != nil {
						slog.Error("failed to load sboms", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						continue
					}

					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback

					opened, closed, newState, err := runner.scanService.ScanNormalizedSBOM(stageCtx, tx, org, project, asset, assetVersions[i], artifact, bom, "system", nil)

					// an artifact with no SBOMs is not an error - it just has
					// nothing to scan, and ScanNormalizedSBOM returns early
					if err != nil {
						tx.Rollback()
						slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						continue
					}

					if runner.debugOptions.DryRun {
						tx.Rollback()

						slog.Info("[DRY-RUN] finished", "open", len(opened), "closed", len(closed), "newState", len(newState))

					} else {
						tx.Commit()
					}

				}
				slog.Info(fmt.Sprintf("scanned asset version %d/%d", i, len(assetVersions)), "time", time.Since(start), "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
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
			if !runner.stageEnabled("SyncUpstream") {
				out <- assetWithDetails
				continue
			}
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			vexRefs, err := runner.externalReferenceRepository.FindByAssetID(assetWithDetails.ctx, runner.db, asset.ID)
			if err != nil {
				slog.Error("failed to fetch vex references for asset", "error", err, "assetID", asset.ID)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch vex references: %w", err),
				}
				continue
			}

			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.sync-upstream")
			errs := make([]error, 0)

			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback

			rules, valid, invalid := runner.scanService.FetchVexFromUpstream(stageCtx, asset.ID, utils.Map(vexRefs, func(el models.ExternalReference) string {
				return el.URL
			}))

			if err := runner.externalReferenceRepository.SaveBatch(stageCtx, tx, append(valid, invalid...)); err != nil {
				slog.Error("could not store vex external reference", "err", err)
			}

			if err := runner.ingestVEXRules(stageCtx, tx, map[uuid.UUID]models.Asset{asset.ID: asset}, map[uuid.UUID][]models.VEXRule{asset.ID: rules}); err != nil {
				slog.Error("could not ingest vex rules", "err", err)
			}

			if runner.debugOptions.DryRun {
				tx.Rollback()
			} else {
				tx.Commit()
			}

			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
					if _, _, err := runner.scanService.SyncArtifactUpstreamSBOMSources(stageCtx, tx, org, project, asset, assetVersions[i], artifact, "system", nil); err != nil {
						slog.Error("failed to sync upstream for artifact", "error", err, "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						tx.Rollback()
						continue
					}

					slog.Info("synced upstream for asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)

					if runner.debugOptions.DryRun {
						tx.Rollback()
					} else {
						tx.Commit()
					}
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

// ApplyVEXRules re-applies this asset's VEX rules on a schedule, not only at
// rule-creation time or against whatever a scan just found. This is what catches
// a rule that starts matching a vuln later - e.g. an upstream rule ingested by
// SyncUpstream above, or a rule whose CEL expression changed since it last ran.
//
// False-positive/accepted rules are only evaluated against currently open vulns
// (closing an already-closed vuln again is a no-op anyway). Reopen rules are the
// mirror image: they only make sense against vulns a previous rule (or a person)
// already accepted, so they're evaluated against accepted vulns instead.
func (runner *DaemonRunner) ApplyVEXRules(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("apply vex rules panic")
		}()

		for assetWithDetails := range input {
			if !runner.stageEnabled("ApplyVEXRules") {
				out <- assetWithDetails
				continue
			}
			asset := assetWithDetails.asset

			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.apply-vex-rules")

			rules, err := runner.vexRuleRepository.FindByAssetID(stageCtx, runner.db, asset.ID)
			if err != nil {
				slog.Error("failed to fetch VEX rules for asset", "error", err, "assetID", asset.ID)
				errChan <- pipelineError{asset: asset, err: fmt.Errorf("could not fetch VEX rules: %w", err)}
				span.End()
				out <- assetWithDetails
				continue
			}
			runner.applyVEXRules(stageCtx, asset, rules)

			span.End()
			out <- assetWithDetails
		}
	}()
	return out
}

// applyVEXRules mirrors what VEXRuleController.Create does for a single
// newly-created rule, generalized to every rule currently enabled for the asset:
// group rules by the vuln state services.VulnStateForVEXRuleEventType says they
// apply to, fetch one representative vuln per distinct signature in that state,
// let the VEX rule service compute which group events that implies, and persist
// them. Errors are logged rather than propagated to the pipeline's error channel -
// a failure here shouldn't stop the rest of this asset's pipeline stages.
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

		if runner.debugOptions.DryRun {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}
}

func (runner *DaemonRunner) CollectStats(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("collect stats panic")
		}()

		for assetWithDetails := range input {
			if !runner.stageEnabled("CollectStats") {
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.collect-stats")
			errs := make([]error, 0)
			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
					if err := runner.statisticsService.UpdateArtifactRiskAggregation(stageCtx, tx, &artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
						tx.Rollback()
						slog.Error("could not recalculate risk history", "err", err)
						errs = append(errs, err)
						continue
					}
					if runner.debugOptions.DryRun {
						tx.Rollback()
					} else {
						tx.Commit()
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
			if !runner.stageEnabled("RecalculateRiskForVulnerabilities") {
				out <- assetWithDetails
				continue
			}
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
				tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
				_, err = runner.dependencyVulnService.RecalculateRawRiskAssessment(stageCtx, tx, "system", dependencyVulns, "System recalculated raw risk assessment", assetWithDetails.asset)
				if err != nil {
					tx.Rollback()
					slog.Error("failed to recalculate raw risk assessment for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					errs = append(errs, err)
					continue
				}
				if runner.debugOptions.DryRun {
					tx.Rollback()
				} else {
					tx.Commit()
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
			if !runner.stageEnabled("AutoReopenTickets") {
				out <- assetWithDetails
				continue
			}
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
				event := models.NewReopenedEvent(vuln.ID, dtos.VulnTypeDependencyVuln, "system", fmt.Sprintf("Automatically reopened since the vulnerability was accepted more than %d days ago", *asset.VulnAutoReopenAfterDays), false, nil)

				tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
				if err := runner.dependencyVulnRepository.ApplyAndSave(stageCtx, tx, &vuln, &event); err != nil {
					tx.Rollback()
					slog.Error("failed to apply and save vulnerability event", "vulnerabilityID", vuln.ID, "error", err)
					errs = append(errs, err)
					continue
				}
				if runner.debugOptions.DryRun {
					tx.Rollback()
				} else {
					tx.Commit()
				}
				slog.Info("reopened vulnerability since it was accepted more than the configured time", "vulnerabilityID", vuln.ID, "assetID", asset.ID, "reopenAfterDays", *asset.VulnAutoReopenAfterDays)
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
			if !runner.stageEnabled("DeleteOldAssetVersions") {
				out <- assetWithDetails
				continue
			}
			stageCtx, span := daemonTracer.Start(assetWithDetails.ctx, "pipeline.delete-old-versions")
			tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback
			_, err := runner.assetVersionRepository.DeleteOldAssetVersionsOfAsset(stageCtx, tx, assetWithDetails.asset.ID, 7)
			if err != nil {
				tx.Rollback()
				slog.Error("Failed to delete old asset versions", "err", err)
				failStage(assetWithDetails.ctx, span, err)
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not delete old asset versions: %w", err),
				}
				continue
			}
			if runner.debugOptions.DryRun {
				tx.Rollback()
			} else {
				tx.Commit()
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

// StartBenchmarkJobs runs the asset pipeline over all assets with every database
// write rolled back. stages limits the run to the given pipeline stages, see
// DebugOptions.LimitToStages for the valid names - pass nil to run all of them.
func (runner *DaemonRunner) StartBenchmarkJobs(ctx context.Context, stages []string) {
	runner.SetDebugOptions(DebugOptions{
		DryRun:        true,
		LimitToStages: stages,
	})

	errChan := make(chan pipelineError, 100)
	runner.collectErrors(errChan)

	runner.runPipeline(ctx, runner.FetchAllAssetIDs(ctx), errChan)
}
