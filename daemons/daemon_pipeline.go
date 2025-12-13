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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"errors"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/prometheus/client_golang/prometheus"
)

type assetWithProjectAndOrg struct {
	asset         models.Asset
	assetVersions []models.AssetVersion // artifacts are prefetched!
	project       models.Project
	org           models.Org
}

type pipelineError struct {
	asset models.Asset
	err   error
}

func (runner DaemonRunner) runPipeline(idsChan <-chan uuid.UUID, errChan chan<- pipelineError) {

	// fetch asset details
	assetsChan := monitorStage(monitoring.FetchAssetStageDuration, runner.FetchAssetDetails)(idsChan, errChan)
	// scan assets
	scannedAssetsChan := monitorStage(monitoring.ScanDaemonDuration, runner.ScanAsset)(assetsChan, errChan)
	// sync upstream
	syncedUpstreamChan := monitorStage(monitoring.UpstreamSyncDuration, runner.SyncUpstream)(scannedAssetsChan, errChan)
	// auto-reopen tickets
	autoReopenedVulnsChan := monitorStage(monitoring.ReopenVulnsStageDuration, runner.AutoReopenTickets)(syncedUpstreamChan, errChan)
	// recalculate risk for vulnerabilities
	recalculatedRiskChan := monitorStage(monitoring.RecalculateRawRiskAssessmentsDuration, runner.RecalculateRiskForVulnerabilities)(autoReopenedVulnsChan, errChan)
	// sync tickets
	syncedTicketsChan := monitorStage(monitoring.SyncTicketDuration, runner.SyncTickets)(recalculatedRiskChan, errChan)
	// collect stats
	ch := monitorStage(monitoring.StatisticsUpdateDuration, runner.CollectStats)(syncedTicketsChan, errChan)
	utils.WaitForChannelDrain(ch)
	// we can close the error channel now
	// since it is a chan<-pipelineError we can be sure that all errors have been sent
	close(errChan)
}

// this creates a channel which will be used to pipeline asset processing in daemons
func (runner DaemonRunner) RunAssetPipeline() {
	// fetch all assets from the database
	errChan := make(chan pipelineError, 100)
	runner.collectErrors(errChan)
	idsChan := runner.FetchAssetIDs()
	runner.runPipeline(idsChan, errChan)
}

func (runner DaemonRunner) RunDaemonPipelineForAsset(assetID uuid.UUID) error {
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
	runner.runPipeline(idsChan, errChan)
	<-wg

	return pErr.err
}

func monitorStage[In any, Out any](
	hist prometheus.Histogram,
	stageFunc func(<-chan In, chan<- pipelineError) <-chan Out,
) func(<-chan In, chan<- pipelineError) <-chan Out {
	return func(input <-chan In, errChan chan<- pipelineError) <-chan Out {
		output := make(chan Out)
		go func() {
			defer close(output)
			for item := range stageFunc(input, errChan) {
				// record metrics
				start := time.Now()
				output <- item
				hist.Observe(time.Since(start).Minutes())
			}
		}()
		return output
	}
}

func (runner DaemonRunner) collectErrors(input <-chan pipelineError) {
	go func() {
		for assetWithDetails := range input {
			slog.Error("error during asset pipeline", "assetID", assetWithDetails.asset.ID, "err", assetWithDetails.err)

			asset := assetWithDetails.asset
			errMsg := assetWithDetails.err.Error()
			asset.PipelineError = &errMsg
			asset.PipelineLastRun = time.Now()
			err := runner.assetRepository.Save(nil, &asset)
			if err != nil {
				monitoring.Alert("could not save pipeline error to asset", err)
			}
		}
	}()
}

func (runner DaemonRunner) FetchAssetIDs() <-chan uuid.UUID {
	out := make(chan uuid.UUID)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("fetch asset ids panic")
		}()
		var assets []models.Asset
		// fetch ALL asset ids from the database
		err := runner.assetRepository.GetDB(nil).Model(&models.Asset{}).Where("pipeline_last_run < ?", time.Now().Add(-1*time.Hour)).Select("ID").Find(&assets).Error
		if err != nil {
			monitoring.Alert("could not fetch asset ids. Cannot run runner. This is critical since all background jobs will be stuck.", err)
		}
		for _, asset := range assets {
			out <- asset.ID
		}
	}()
	return out
}

// fetches the asset details for each element in the input channel
// this way WE HOPE to no overload the database with too big queries or too many concurrent requests
func (runner DaemonRunner) FetchAssetDetails(input <-chan uuid.UUID, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("fetch asset details panic")
		}()
		for assetID := range input {
			asset, err := runner.assetRepository.Read(assetID)
			if err != nil {
				slog.Error("could not fetch asset in runner", "assetID", assetID, "err", err)
				errChan <- pipelineError{
					asset: models.Asset{Model: models.Model{ID: assetID}},
					err:   fmt.Errorf("could not fetch asset: %w", err),
				}
				continue
			}

			assetVersions, err := runner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(nil, asset.ID)
			if err != nil {
				slog.Error("could not fetch asset versions in runner", "assetID", asset.ID, "err", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch asset versions: %w", err),
				}
				continue
			}

			project, err := runner.projectRepository.Read(asset.ProjectID)
			if err != nil {
				slog.Error("could not fetch project in runner", "assetID", asset.ID, "err", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}
			org, err := runner.orgRepository.Read(project.OrganizationID)
			if err != nil {
				slog.Error("could not fetch org in runner", "assetID", asset.ID, "err", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}

			// mark the asset as processed - so that we do not process it again, even if the pipeline takes longer than an hour
			asset.PipelineLastRun = time.Now()
			asset.PipelineError = nil
			err = runner.assetRepository.Save(nil, &asset)
			if err != nil {
				monitoring.Alert("could not save last pipeline run. The asset will be processed whenever the pipeline runs again (usually 5 minutes)", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not fetch project: %w", err),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "FetchAssetDetails", "assetID", asset.ID)
			out <- assetWithProjectAndOrg{
				asset:         asset,
				assetVersions: assetVersions,
				project:       project,
				org:           org,
			}
		}
	}()
	return out
}

func (runner DaemonRunner) SyncTickets(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("sync tickets panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if !commonint.IsConnectedToThirdPartyIntegration(asset) {
				slog.Info("asset not connected to third party integration - skipping SyncTickets", "assetID", asset.ID)
				out <- assetWithDetails
				continue
			}
			errs := make([]error, 0)
			for _, assetVersion := range assetWithDetails.assetVersions {
				err := runner.dependencyVulnService.SyncAllIssues(assetWithDetails.org, assetWithDetails.project, asset, assetVersion)
				if err != nil {
					slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", asset.ID, "error", err)
					errs = append(errs, err)
					continue
				}
			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not sync tickets: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "SyncTickets", "assetID", assetWithDetails.asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) ResolveDifferencesInTicketState(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("resolve differences in ticket state panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if !commonint.IsConnectedToThirdPartyIntegration(asset) {
				continue
			}
			depVulns, err := runner.dependencyVulnRepository.GetAllVulnsByAssetIDWithTicketIDs(nil, asset.ID)

			if err != nil {
				slog.Error("could not get dependency vulns for asset", "assetID", asset.ID, "err", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not get dependency vulns: %w", err),
				}
				continue
			}

			// build new client each time for authentication
			err = runner.integrationAggregate.CompareIssueStatesAndResolveDifferences(asset, depVulns)
			if err != nil {
				slog.Error("could not compare ticket states", "err", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not compare ticket states: %w", err),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "ResolveDifferencesInTicketState", "assetID", assetWithDetails.asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) ScanAsset(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("scan panic")
		}()

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			errs := make([]error, 0)
			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					components, err := runner.componentRepository.LoadComponents(nil, assetVersions[i].Name, assetVersions[i].AssetID, &artifact.ArtifactName)
					if err != nil {
						slog.Error("failed to load components", "error", err)
						errs = append(errs, err)
						continue
					}

					bom, err := runner.assetVersionService.BuildSBOM(asset, assetVersions[i], artifact.ArtifactName, "", components)
					if err != nil {
						slog.Error("error when building SBOM")
						errs = append(errs, err)
						continue
					}
					if len(components) <= 0 {
						continue
					} else {
						_, _, _, err = runner.scanService.ScanNormalizedSBOMWithoutEventHandling(org, project, asset, assetVersions[i], artifact, bom, "system")
					}

					if err != nil {
						slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						errs = append(errs, err)
						continue
					}

					slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
				}
			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not scan asset: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "ScanAsset", "assetID", asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) SyncUpstream(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
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
			errs := make([]error, 0)

			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					rootNodes, err := runner.componentService.FetchInformationSources(&artifact)
					if err != nil {
						slog.Error("failed to fetch root nodes for artifact", "artifact", artifact.ArtifactName, "assetVersion", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
						errs = append(errs, err)
						continue
					}

					upstreamURLs := utils.UniqBy(utils.Filter(utils.Map(rootNodes, func(el models.ComponentDependency) string {
						_, origin := normalize.RemoveOriginTypePrefixIfExists(el.DependencyPurl)
						return origin
					}), func(el string) bool {
						return strings.HasPrefix(el, "http")
					}), func(el string) string {
						return el
					})

					vexReports, _, _ := runner.artifactService.FetchBomsFromUpstream(artifact.ArtifactName, artifact.AssetVersionName, upstreamURLs)

					_, err = runner.artifactService.SyncUpstreamBoms(vexReports, org, project, asset, assetVersions[i], artifact, "system")
					if err != nil {
						slog.Error("failed to sync VEX reports", "artifact", artifact.ArtifactName, "assetVersion", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
						errs = append(errs, err)
						continue
					}
				}
			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not sync upstream: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "SyncUpstream", "assetID", asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) CollectStats(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("collect stats panic")
		}()

		for assetWithDetails := range input {
			errs := make([]error, 0)
			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					start := time.Now()
					if err := runner.statisticsService.UpdateArtifactRiskAggregation(&artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
						slog.Error("could not recalculate risk history", "err", err)
						errs = append(errs, err)
						continue
					}

					slog.Info("updated statistics for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", artifact.AssetVersionName, "assetID", artifact.AssetID)
					monitoring.StatisticsUpdateDuration.Observe(time.Since(start).Minutes())
				}
			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not collect stats: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "CollectStats", "assetID", assetWithDetails.asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) RecalculateRiskForVulnerabilities(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("recalculate risk for vulnerabilities panic")
		}()

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			errs := make([]error, 0)

			for _, assetVersion := range assetVersions {

				// get all dependencyVulns of the asset
				dependencyVulns, err := runner.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
				if err != nil {
					slog.Error("failed to get dependency vulns for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					errs = append(errs, err)
					continue
				}

				if len(dependencyVulns) == 0 {
					continue
				}

				_, err = runner.dependencyVulnService.RecalculateRawRiskAssessment(nil, "system", dependencyVulns, "System recalculated raw risk assessment", assetVersion.Asset)
				if err != nil {
					slog.Error("failed to recalculate raw risk assessment for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					errs = append(errs, err)
					continue
				}

			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: assetWithDetails.asset,
					err:   fmt.Errorf("could not recalculate risk: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "RecalculateRiskForVulnerabilities", "assetID", assetWithDetails.asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) AutoReopenTickets(input <-chan assetWithProjectAndOrg, errChan chan<- pipelineError) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer func() {
			close(out)
			monitoring.RecoverPanic("auto reopen tickets panic")
		}()

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if asset.VulnAutoReopenAfterDays == nil || *asset.VulnAutoReopenAfterDays <= 0 {
				slog.Info("finished pipeline stage", "stage", "AutoReopenTickets", "assetID", assetWithDetails.asset.ID)
				out <- assetWithDetails
				continue
			}
			// convert days to time.Duration
			reopenAfterDuration := time.Duration(*asset.VulnAutoReopenAfterDays) * 24 * time.Hour

			// get all closed/accepted vulnerabilities for the asset version
			vulnerabilities, err := runner.dependencyVulnRepository.GetAllByAssetIDAndState(nil, asset.ID, dtos.VulnStateAccepted, reopenAfterDuration)
			if err != nil {
				slog.Error("failed to get closed/accepted vulnerabilities for asset", "assetID", asset.ID, "error", err)
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not get closed/accepted vulnerabilities: %w", err),
				}
				continue
			}

			errs := make([]error, 0)
			for _, vuln := range vulnerabilities {
				// create a new event for the vulnerability
				event := models.NewReopenedEvent(vuln.ID, dtos.VulnTypeDependencyVuln, "system", fmt.Sprintf("Automatically reopened since the vulnerability was accepted more than %d days ago", *asset.VulnAutoReopenAfterDays), dtos.UpstreamStateInternal)

				if err := runner.dependencyVulnRepository.ApplyAndSave(nil, &vuln, &event); err != nil {
					slog.Error("failed to apply and save vulnerability event", "vulnerabilityID", vuln.ID, "error", err)
					errs = append(errs, err)
					continue
				} else {
					slog.Info("reopened vulnerability since it was accepted more than the configured time", "vulnerabilityID", vuln.ID, "assetID", asset.ID, "reopenAfterDays", *asset.VulnAutoReopenAfterDays)
				}
			}
			if len(errs) > 0 {
				errChan <- pipelineError{
					asset: asset,
					err:   fmt.Errorf("could not auto-reopen tickets: %v", errors.Join(errs...)),
				}
				continue
			}
			slog.Info("finished pipeline stage", "stage", "AutoReopenTickets", "assetID", assetWithDetails.asset.ID)
			out <- assetWithDetails
		}
	}()
	return out
}
