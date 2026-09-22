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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
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
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/statemachine"
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

	row := conn.QueryRow(ctx, `SELECT COUNT(*)>0 FROM information_schema.tables 
			WHERE table_catalog = 'devguard'
			AND table_schema = 'public'
			AND table_name = 'vuln_paths';`)
	var vulnInfoExists bool
	err = row.Scan(&vulnInfoExists)
	if err != nil {
		return err
	}
	vulnInfoExists = false
	if !vulnInfoExists {

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
		_, err = tx.CopyFrom(ctx, pgx.Identifier{"purl_mapping"}, []string{"purl", "affected_component_id", "fixed_version"}, pgx.CopyFromSlice(len(purlAffectedComponents), func(i int) ([]any, error) {
			return []any{purlAffectedComponents[i].purl, purlAffectedComponents[i].affectedComponentID, purlAffectedComponents[i].fixedVersion}, nil
		}))
		if err != nil {
			return fmt.Errorf("could not copy rows into temporary table: %w", err)
		}

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

		_, err = tx.Exec(ctx, `
			CREATE TABLE vuln_paths (
				component_purl text,
				root uuid,
				path uuid[]
			);`)
		if err != nil {
			return fmt.Errorf("could not create table for vuln paths: %w", err)
		}

		err = tx.Commit(ctx)
		if err != nil {
			panic(err)
		}

		affectedPurls := utils.DeduplicateSlice(purlAffectedComponents, func(purl purlAffectedComponent) string { return purl.purl })

		slog.Info("start scanning affected purls", "amount", len(affectedPurls))
		start = time.Now()
		var purlBatchSize = len(affectedPurls)
		group := &errgroup.Group{}
		resultsChannel := make(chan purlPathResult)
		vulnPathColumns := []string{"component_purl", "root", "path"}
		for start := 0; start < len(affectedPurls); start += purlBatchSize {
			timer := time.Now()
			end := min(start+purlBatchSize, len(affectedPurls))
			group.Go(func() error {
				_, err = runner.GetPathsForPurls(ctx, resultsChannel, utils.Map(affectedPurls[start:end], func(pac purlAffectedComponent) string { return pac.purl }))
				return err
			})

			var groupErr error
			go func() {
				groupErr = group.Wait()
				close(resultsChannel)
			}()

			const batchSize = 4000
			rowsBuffer := make([]vulnPath, 0, batchSize*1.25) // 75% pctfree
			for result := range resultsChannel {
				purl := result.Purl
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
						Path: path,
						Root: path[len(path)-1],
					})
				}

				if len(rowsBuffer) >= batchSize {
					slog.Info("streaming batch to database", "amount", len(rowsBuffer))
					_, err = conn.CopyFrom(ctx, pgx.Identifier{"vuln_paths"}, vulnPathColumns, pgx.CopyFromSlice(len(rowsBuffer), func(i int) ([]any, error) {
						return []any{rowsBuffer[i].Purl, rowsBuffer[i].Root, rowsBuffer[i].Path}, nil
					}))
					if err != nil {
						return fmt.Errorf("could not copy vuln paths into table: %w", err)
					}
					rowsBuffer = rowsBuffer[:0]
				}
			}

			if groupErr != nil {
				return fmt.Errorf("could not scan purl batch: %w", groupErr)
			}

			slog.Info(fmt.Sprintf("finished scanning batch %d out of %f", start/purlBatchSize, math.Ceil(float64(len(affectedPurls))/float64(purlBatchSize))), "time", time.Since(timer))
		}

		slog.Info("finished scanning all purls", "time", time.Since(start))

		start = time.Now()
		// now materialize the new dependency vulns from the scan data
		_, err = conn.Exec(ctx, `
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
		_, err = conn.Exec(ctx, `CREATE INDEX artifact_lookup_idx ON public.new_dependency_vulns (asset_id, asset_version_name, artifact_name);`)
		if err != nil {
			return fmt.Errorf("could not create index on vuln_path artifact lookup: %w", err)
		}
		slog.Info("finished materializing new dependency vulns", "time", time.Since(start))
	} else {
		slog.Info("vuln info already present, skipping scanning")
	}

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
	for i, assetID := range assetIDs {
		start := time.Now()
		err = runner.handleScanResultForAsset(ctx, conn, assetID)
		if err != nil {
			return fmt.Errorf("could not handle scan result: %w", err)
		}
		slog.Info(fmt.Sprintf("finished asset %d/%d", i, len(assetIDs)), "time", time.Since(start))
	}

	slog.Info("finished all handle scan results", "time", time.Since(startHandling))

	return nil
}

type vulnPath struct {
	Purl string
	Root uuid.UUID
	Path []uuid.UUID
}

func (runner *DaemonRunner) handleScanResultForAsset(ctx context.Context, conn *pgxpool.Conn, assetID uuid.UUID) error {
	assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(ctx, nil, assetID)
	if err != nil {
		return fmt.Errorf("could not fetch asset versions for asset: %w", err)
	}

	var asset models.Asset
	err = runner.db.Raw(`SELECT * FROM assets WHERE id = ?`, assetID).Find(&asset).Error
	if err != nil {
		return fmt.Errorf("could not fetch asset details: %w", err)
	}

	for _, assetVersion := range assetVersions {
		for _, artifact := range assetVersion.Artifacts {
			foundVulns, err := runner.fetchNewVulnsForArtifact(ctx, conn, artifact)
			if err != nil {
				return fmt.Errorf("could not query found vulns for artifact: %w", err)
			}
			slog.Info("finished fetching vulns, start handling results", "amount", len(foundVulns))

			start := time.Now()
			err = runner.HandleScanResultBatch(ctx, foundVulns, artifact.ArtifactName, artifact.AssetVersionName, asset)
			if err != nil {
				return fmt.Errorf("could not handle scan results: %w", err)
			}
			slog.Info("handled scan result", "time", time.Since(start))
		}
	}
	return nil
}

func (runner *DaemonRunner) HandleScanResultBatch(ctx context.Context, dependencyVulns []models.DependencyVuln, artifactName, assetVersionName string, asset models.Asset) error {
	existingDependencyVulns, err := runner.dependencyVulnRepository.ListByAssetAndAssetVersion(ctx, nil, assetVersionName, asset.ID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return err
	}

	// get all vulns from other branches
	existingVulnsOnOtherBranch, err := runner.dependencyVulnRepository.GetNotFixedDependencyVulnsByOtherAssetVersions(ctx, nil, assetVersionName, asset.ID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns on default branch", "err", err)
		return err
	}

	diff := statemachine.DiffScanResults(artifactName, dependencyVulns, existingDependencyVulns)
	// remove from fixed vulns and fixed on this artifact name all vulns, that have more than a single path to them
	// this means, that another source is still saying, its part of this artifact
	unfixablePurls, err := runner.fetchPurlsInMultipleSBOMs(ctx, asset.ID, assetVersionName, artifactName)
	if err != nil {
		return fmt.Errorf("could not fetch purls in multiple sboms: %w", err)
	}
	filterPredicate := func(dv models.DependencyVuln) bool {
		_, ok := unfixablePurls[dv.ComponentPurl]
		return !ok
	}

	tx, err := runner.pgxpool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	fixedOnThisArtifactName := utils.Filter(diff.RemovedFromArtifact, filterPredicate)

	branchDiff := statemachine.DiffVulnsBetweenBranches(utils.Map(diff.NewlyDiscovered, utils.Ptr), utils.Map(existingVulnsOnOtherBranch, utils.Ptr))

	// make sure to first create a user detected event for vulnerabilities with just upstream events
	// this way we preserve the event history
	if err := runner.DetectedExistingVulnOnDifferentBranch(ctx, tx, artifactName, branchDiff.ExistingOnOtherBranches, asset); err != nil {
		slog.Error("error when trying to add events for existing vulnerability on different branch")
		return err
	}
	// We can create the newly found one without checking anything
	if err := runner.DetectedDependencyVulns(ctx, tx, "system", nil, artifactName, utils.DereferenceSlice(branchDiff.NewToAllBranches), asset); err != nil {
		return err
	}

	err = runner.DetectedDependencyVulnInAnotherArtifact(ctx, tx, diff.NewInArtifact, artifactName)
	if err != nil {
		slog.Error("error when trying to associate new artifact to vulnerabilities")
		return err
	}

	err = runner.DidNotDetectDependencyVulnInArtifactAnymore(ctx, tx, fixedOnThisArtifactName, artifactName)
	if err != nil {
		slog.Error("error when trying to remove artifact association from vulnerabilities")
		return err
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return nil
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
		events[i] = models.NewDetectedEvent(dependencyVulns[i].CalculateHash(), dtos.VulnTypeDependencyVuln, userID, riskReport, artifactName, false, userAgent)
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
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_events"}, []string{"created_at", "type", "user_id", "justification", "mechanical_justification", "arbitrary_json_data", "original_asset_version_name", "created_by_vex_rule", "dependency_vuln_id", "user_agent", "vex_rule_id", "asset_signature"}, pgx.CopyFromSlice(len(events), func(i int) ([]any, error) {
		ev := events[i]
		// events copied from other branches keep their original timestamp
		createdAt := ev.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		return []any{createdAt, string(ev.Type), ev.UserID, ev.Justification, string(ev.MechanicalJustification), ev.ArbitraryJSONData, ev.OriginalAssetVersionName, ev.CreatedByVexRule, ev.DependencyVulnID, ev.UserAgent, ev.VexRuleID, ev.AssetSignature}, nil
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

func (runner *DaemonRunner) fetchNewVulnsForArtifact(ctx context.Context, conn *pgxpool.Conn, artifact models.Artifact) ([]models.DependencyVuln, error) {
	// the vuln id only hashes cve and path, so rows differing only in fixed_version (multiple affected components) must collapse into one vuln
	rows, err := conn.Query(ctx, `
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

func (runner *DaemonRunner) fetchPurlsInMultipleSBOMs(ctx context.Context, assetID uuid.UUID, assetVersionName, artifactName string) (map[string]struct{}, error) {
	rows, err := runner.pgxpool.Query(ctx, `
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

type SBOM struct {
	AssetID          uuid.UUID
	AssetVersionName string
	ArtifactName     string
	Source           string
}
type vulnIdentity struct {
	ComponentPurl string
	CVE           string
	FixedVersion  *string
	Path          []string
}
type purlPathResult struct {
	Purl  string
	Paths [][]uuid.UUID // vulnerable node -> ... -> sbom root
	// sboms reached by more than maxPathsPerRoot paths, none of their paths are kept
	ExplodedRoots []uuid.UUID
}

func (runner *DaemonRunner) GetPathsForPurls(ctx context.Context, results chan purlPathResult, purls []string) (map[string][][]uuid.UUID, error) {
	start := time.Now()
	// calculate map size upper bound
	row := runner.pgxpool.QueryRow(ctx, `SELECT COUNT(*) FROM sbom_merkle_nodes;`)

	var count int
	err := row.Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("could not query count of nodes: %w", err)
	}

	// leaf rows carry a NULL child and are no edges
	edgeRows, err := runner.pgxpool.Query(ctx, `SELECT subtree_hash,direct_dependency_subtree_hash FROM sbom_merkle_edges WHERE direct_dependency_subtree_hash IS NOT NULL;`)
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

	purlRows, err := runner.pgxpool.Query(ctx, `
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
	rootRows, err := runner.pgxpool.Query(ctx, `
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
					if len(pathsPerRoot[node]) == maxPathsPerRoot {
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

const maxPathsPerRoot = 12

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
