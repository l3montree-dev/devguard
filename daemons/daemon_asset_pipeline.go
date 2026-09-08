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
	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"gorm.io/datatypes"
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

	slog.Info("start collecting all dependencies")
	start := time.Now()
	purlRows, err := conn.Query(ctx, `SELECT DISTINCT dependency_id FROM public.component_dependencies;`)
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

	affectedPurls := make([]purlAffectedComponent, 0, len(candidates))
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
				affectedPurls = append(affectedPurls, purlAffectedComponent{
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
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"purl_mapping"}, []string{"purl", "affected_component_id", "fixed_version"}, pgx.CopyFromSlice(len(affectedPurls), func(i int) ([]any, error) {
		return []any{affectedPurls[i].purl, affectedPurls[i].affectedComponentID, affectedPurls[i].fixedVersion}, nil
	}))
	if err != nil {
		return fmt.Errorf("could not copy rows into temporary table: %w", err)
	}

	slog.Info("successfully populated temporary table", "time", time.Since(start))

	_, err = tx.Exec(ctx, `
	ALTER TABLE purl_mapping 
		ADD CONSTRAINT purl_mapping_pkey PRIMARY KEY (purl, affected_component_id);`)
	if err != nil {
		return fmt.Errorf("could not create primary key on temp table for purl Mapping: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		panic(err)
	}

	// maybe only scan default branches
	avRows, err := conn.Query(ctx, `
	SELECT DISTINCT cd.component_id, cd.asset_id, cd.asset_version_name FROM public.component_dependencies cd 
	WHERE cd.component_id LIKE 'artifact:%';`)
	if err != nil {
		return fmt.Errorf("could not fetch all asset version to scan: %w", err)
	}
	defer avRows.Close()

	type mapKey struct {
		AssetVersionName, AssetID string
	}
	var key mapKey
	var componentID, assetID, assetVersionName string
	avToArtifacts := make(map[mapKey][]string, 1024)
	for avRows.Next() {
		err = avRows.Scan(&componentID, &assetID, &assetVersionName)
		if err != nil {
			return fmt.Errorf("could not scan asset version row: %w", err)
		}
		key = mapKey{AssetVersionName: assetVersionName, AssetID: assetID}
		avToArtifacts[key] = append(avToArtifacts[key], strings.TrimPrefix(componentID, "artifact:"))
	}
	avRows.Close()
	if err := avRows.Err(); err != nil {
		return err
	}

	allAssetVersions := make([]assetVersionInAsset, 0, len(avToArtifacts))
	for key, artifacts := range avToArtifacts {
		parsedAssetID, err := uuid.Parse(key.AssetID)
		if err != nil {
			return fmt.Errorf("could not parse assetID: %w", err)
		}
		allAssetVersions = append(allAssetVersions, assetVersionInAsset{
			AssetVersionName: key.AssetVersionName,
			AssetID:          parsedAssetID,
			Artifacts:        artifacts,
		})
	}

	slog.Info("finished collecting asset versions with components", "amount", len(allAssetVersions))

	start = time.Now()
	const maxNumberOfGoRoutines = 8
	scanningWaitGroup, scanCtx := errgroup.WithContext(ctx)
	scanningWaitGroup.SetLimit(maxNumberOfGoRoutines)

	allResults := make([]models.DependencyVuln, 0, len(affectedPurls)*8)
	resultsChannel := make(chan *models.DependencyVuln, maxNumberOfGoRoutines*16)

	go func() {
		for vuln := range resultsChannel {
			allResults = append(allResults, *vuln)
		}
	}()

	for i, av := range allAssetVersions {
		if i%5 == 0 {
			slog.Info(fmt.Sprintf("Scanning asset versions, processing %d/%d", i, len(allAssetVersions)), "time", time.Since(start))
		}
		if err := runner.ScanAssetVersion(scanCtx, av, resultsChannel, isPurlAffected); err != nil {
			slog.Error("could not scan asset version", "av_name", av.AssetVersionName, "assetID", av.AssetID, "error", err)
		}
		// scanningWaitGroup.Go(func() error {
		// 	if err := runner.ScanAssetVersion(scanCtx, av, resultsChannel, isPurlAffected); err != nil {
		// 		slog.Error("could not scan asset version", "av_name", av.AssetVersionName, "assetID", av.AssetID, "error", err)
		// 	}
		// 	return nil
		// })
	}
	// scanningWaitGroup.Wait()
	close(resultsChannel)

	slog.Info("finished collecting all paths to all purls", "amount", len(allResults), "time", time.Since(start))
	return nil
}

type assetVersionInAsset struct {
	AssetVersionName string
	AssetID          uuid.UUID
	Artifacts        []string
}

type purlWithPaths struct {
	Purl  string
	Paths []string
}

func (runner *DaemonRunner) ScanAssetVersion(scanCtx context.Context, assetVersion assetVersionInAsset, results chan *models.DependencyVuln, purlLookUp map[string]struct{}) error {
	bom, err := runner.assetVersionService.LoadFullSBOMGraph(scanCtx, nil, models.AssetVersion{Name: assetVersion.AssetVersionName, AssetID: assetVersion.AssetID})
	if err != nil {
		return fmt.Errorf("could not build SBOM for asset version")
	}

	sbomCache := map[string][]*models.DependencyVuln{}

	for _, artifactName := range assetVersion.Artifacts {
		currentBom := *bom
		// remove all other artifacts from the bom
		err := currentBom.ScopeToArtifact(artifactName)
		if err != nil {
			// If artifact node is not reachable, it means the artifact has no components (empty artifact)
			// This is a valid scenario, so we return early with no vulnerabilities
			if errors.Is(err, normalize.ErrNodeNotReachable) {
				slog.Warn("artifact has no components, skipping scan", "artifactName", artifactName)
				continue
			}
			slog.Error("could not scope bom to artifact", "err", err)
			return err
		}

		sbomHash := currentBom.GetSBOMHash()
		vulns, ok := sbomCache[sbomHash]
		if ok {
			slog.Info("hit cache", "hash", sbomHash, "cached vulns amount", len(vulns))
			for i := range vulns {
				vuln := *vulns[i]
				vuln.Artifacts = []models.Artifact{
					{
						ArtifactName:     artifactName,
						AssetVersionName: assetVersion.AssetVersionName,
						AssetID:          assetVersion.AssetID,
					},
				}
				results <- &vuln
			}
			continue
		}

		vulnsInPackage, err := runner.optimizedScan(scanCtx, currentBom, purlLookUp)
		if err != nil {
			slog.Error("could not scan file", "err", err)
			return err
		}

		if artifactName == "pkg:oci/kratos?repository_url=ghcr.io/l3montree-dev/devguard/kratos&arch=amd64&tag=v26.2.0-v1.13.3-amd64" {
			slog.Info("stop")
		}

		dependencyVulns := make([]models.DependencyVuln, 0, len(vulnsInPackage)*2)
		for _, vuln := range vulnsInPackage {
			dependencyVulns = append(dependencyVulns, transformer.VulnInPackageToDependencyVulns(vuln, &currentBom, assetVersion.AssetID, assetVersion.AssetVersionName, artifactName)...)
		}

		dependencyVulns = utils.UniqBy(dependencyVulns, func(f models.DependencyVuln) uuid.UUID {
			return f.CalculateHash()
		})

		for i := range dependencyVulns {
			sbomCache[sbomHash] = append(sbomCache[sbomHash], &dependencyVulns[i])
			results <- &dependencyVulns[i]
		}

		// handle the scan result
		// opened, closed, newState, err := s.HandleScanResult(resultCtx, tx, org, project, asset, &assetVersion, normalizedBom, vulns, artifact.ArtifactName, userID, userAgent)
		// if err != nil {
		// 	slog.Error("could not handle scan result", "err", err)
		// 	return nil, nil, nil, err
		// }

		// // newly opened vulns may already be covered by previously created, still-enabled VEX
		// // rules for this asset (e.g. a rule created before this vulnerability was ever detected).
		// var updatedVulns []models.DependencyVuln
		// var events []models.VulnEvent
		// existingRules, rulesErr := s.vexRuleRepository.FindByAssetID(scanCtx, tx, asset.ID)
		// if rulesErr != nil {
		// 	slog.Error("could not fetch existing VEX rules to apply to newly detected vulns", "err", rulesErr)
		// } else if len(existingRules) > 0 {
		// 	var applyErr error
		// 	if updatedVulns, events, applyErr = ApplyVEXRulesToVulns(scanCtx, existingRules, newState); applyErr != nil {
		// 		slog.Error("could not apply existing VEX rules to newly detected vulns", "err", applyErr)
		// 	} else if len(updatedVulns) > 0 {
		// 		if err := s.dependencyVulnRepository.SaveBatch(scanCtx, tx, updatedVulns); err != nil {
		// 			slog.Error("could not save vulns updated by existing VEX rules", "err", err)
		// 		}
		// 		if err := s.vulnEventRepository.SaveBatch(scanCtx, tx, events); err != nil {
		// 			slog.Error("could not save events from existing VEX rules", "err", err)
		// 		}
		// 	}
		// }
		// //update the state in newState to reflect the changes made by applying the VEX rules
		// newStateMap := make(map[uuid.UUID]models.DependencyVuln)
		// for _, vuln := range newState {
		// 	newStateMap[vuln.ID] = vuln
		// }
		// updatedVulnsMap := make(map[uuid.UUID]models.DependencyVuln)
		// for _, vuln := range updatedVulns {
		// 	updatedVulnsMap[vuln.ID] = vuln
		// }

		// for i, vuln := range newState {
		// 	if updatedVuln, ok := updatedVulnsMap[vuln.ID]; ok {
		// 		vuln.State = updatedVuln.State
		// 		newState[i] = vuln
		// 		newStateMap[vuln.ID] = vuln
		// 	}
		// }

	}
	return nil
}

func (runner *DaemonRunner) optimizedScan(ctx context.Context, bom normalize.SBOMGraph, purlLookUp map[string]struct{}) ([]models.VulnInPackage, error) {
	var affectedPurls []string
	for c := range bom.NodesOfType(normalize.GraphNodeTypeComponent) {
		if c.Component.PackageURL != "" {
			// filter only the affected purls
			if _, ok := purlLookUp[c.Component.PackageURL]; ok {
				affectedPurls = append(affectedPurls, c.Component.PackageURL)
			}
		}
	}

	if len(affectedPurls) == 0 {
		return []models.VulnInPackage{}, nil
	}

	rows, err := runner.pgxpool.Query(ctx, `
	SELECT pm.purl, pm.fixed_version,
		c.id, c.content_hash, c.cve, c.date_published, c.date_last_modified,
		COALESCE(c.description, ''), COALESCE(c.cvss, 0)::real, COALESCE(c."references", ''),
		c.cisa_exploit_add, c.cisa_action_due, c.cisa_required_action, c.cisa_vulnerability_name,
		c.epss::double precision, c.percentile::real, COALESCE(c.vector, ''),
		c.euvd_exploit_add, c.withdrawn, c.cwes
	FROM purl_mapping pm 
	JOIN cve_affected_component cac 
	ON cac.affected_component_id = pm.affected_component_id
	JOIN cves c
	ON c.id = cac.cve_id
	WHERE pm.purl = ANY ($1);`, affectedPurls)
	if err != nil {
		return nil, fmt.Errorf("could not retreive cves for purl: %w", err)
	}
	defer rows.Close()

	var purl string
	var fixedVersion *string
	var cve models.CVE
	// nullable date columns do not fit the models.CVE fields directly
	var datePublished, dateLastModified, cisaExploitAdd, cisaActionDue, euvdExploitAdd, withdrawn *time.Time

	vulnsInPackage := make([]models.VulnInPackage, 0, len(affectedPurls))
	for rows.Next() {
		err = rows.Scan(&purl, &fixedVersion,
			&cve.ID, &cve.ContentHash, &cve.CVE, &datePublished, &dateLastModified,
			&cve.Description, &cve.CVSS, &cve.References,
			&cisaExploitAdd, &cisaActionDue, &cve.CISARequiredAction, &cve.CISAVulnerabilityName,
			&cve.EPSS, &cve.Percentile, &cve.Vector,
			&euvdExploitAdd, &withdrawn, &cve.CWEs)
		if err != nil {
			return nil, fmt.Errorf("could not scan cve row: %w", err)
		}

		cve.DatePublished = utils.OrDefault(datePublished, time.Time{})
		cve.DateLastModified = utils.OrDefault(dateLastModified, time.Time{})
		cve.CISAExploitAdd = (*datatypes.Date)(cisaExploitAdd)
		cve.CISAActionDue = (*datatypes.Date)(cisaActionDue)
		cve.EUVDExploitAdd = (*datatypes.Date)(euvdExploitAdd)
		cve.Withdrawn = (*datatypes.Date)(withdrawn)

		parsedPurl, _ := packageurl.FromString(purl)
		vulnsInPackage = append(vulnsInPackage, models.VulnInPackage{
			CVE:          cve,
			Purl:         parsedPurl,
			CVEID:        cve.CVE,
			FixedVersion: fixedVersion,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("could not read cve rows: %w", err)
	}

	return vulnsInPackage, nil
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
				bom, err := runner.assetVersionService.LoadFullSBOMGraph(stageCtx, nil, assetVersions[i])
				if err != nil {
					slog.Error("failed to load full sbom", "error", err, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
					errs = append(errs, err)
					continue
				}

				slog.Info("start scanning artifacts", "assetVersion", assetVersions[i].Name, "amount artifacts", len(assetVersions[i].Artifacts))
				for _, artifact := range artifacts {
					tx := runner.db.Begin() // nosemgrep: tx-begin-without-defer-rollback

					bom.ClearScope()
					opened, closed, newState, err := runner.scanService.ScanNormalizedSBOM(stageCtx, tx, org, project, asset, assetVersions[i], artifact, bom, "system", nil)

					if err != nil && !errors.Is(err, normalize.ErrNodeNotReachable) {
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
