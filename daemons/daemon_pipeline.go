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
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/prometheus/client_golang/prometheus"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type assetWithProjectAndOrg struct {
	asset         models.Asset
	assetVersions []models.AssetVersion // artifacts are prefetched!
	project       models.Project
	org           models.Org
}

// this creates a channel which will be used to pipeline asset processing in daemons
func (DaemonRunner DaemonRunner) RunAssetPipeline() {
	// fetch all assets from the database
	idsChan := DaemonRunner.FetchAssetIDs()

	// fetch asset details
	assetsChan := monitorStage(monitoring.FetchAssetStageDuration, DaemonRunner.FetchAssetDetails)(idsChan)
	// scan assets
	scannedAssetsChan := monitorStage(monitoring.ScanDaemonDuration, DaemonRunner.ScanAsset)(assetsChan)
	// sync upstream
	syncedUpstreamChan := monitorStage(monitoring.UpstreamSyncDuration, DaemonRunner.SyncUpstream)(scannedAssetsChan)
	// auto-reopen tickets
	autoReopenedVulnsChan := monitorStage(monitoring.ReopenVulnsStageDuration, DaemonRunner.AutoReopenTickets)(syncedUpstreamChan)
	// recalculate risk for vulnerabilities
	recalculatedRiskChan := monitorStage(monitoring.RecalculateRawRiskAssessmentsDuration, DaemonRunner.RecalculateRiskForVulnerabilities)(autoReopenedVulnsChan)
	// sync tickets
	syncedTicketsChan := monitorStage(monitoring.SyncTicketDuration, DaemonRunner.SyncTickets)(recalculatedRiskChan)
	// collect stats
	ch := monitorStage(monitoring.StatisticsUpdateDuration, DaemonRunner.CollectStats)(syncedTicketsChan)
	utils.WaitForChannelDrain(ch)
}

func monitorStage[In any, Out any](
	hist prometheus.Histogram,
	stageFunc func(<-chan In) <-chan Out,
) func(<-chan In) <-chan Out {
	return func(input <-chan In) <-chan Out {
		output := make(chan Out)
		go func() {
			defer close(output)
			for item := range stageFunc(input) {
				// record metrics
				start := time.Now()
				output <- item
				hist.Observe(time.Since(start).Minutes())
			}
		}()
		return output
	}
}

func (DaemonRunner DaemonRunner) FetchAssetIDs() <-chan uuid.UUID {
	out := make(chan uuid.UUID)

	go func() {
		defer close(out)
		var assets []models.Asset
		// fetch ALL asset ids from the database
		err := DaemonRunner.assetRepository.GetDB(nil).Model(&models.Asset{}).Select("ID").Find(&assets).Error
		if err != nil {
			monitoring.Alert("could not fetch asset ids. Cannot run DaemonRunner. This is critical since all background jobs will be stuck.", err)
		}

		for _, asset := range assets {
			out <- asset.ID
		}
	}()
	return out
}

// fetches the asset details for each element in the input channel
// this way WE HOPE to no overload the database with too big queries or too many concurrent requests
func (DaemonRunner DaemonRunner) FetchAssetDetails(input <-chan uuid.UUID) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer close(out)
		for assetID := range input {
			asset, err := DaemonRunner.assetRepository.Read(assetID)
			if err != nil {
				slog.Error("could not fetch asset in DaemonRunner", "assetID", assetID, "err", err)
				continue
			}

			assetVersions, err := DaemonRunner.assetVersionRepository.GetAssetVersionsByAssetIDWithArtifacts(nil, asset.ID)
			if err != nil {
				slog.Error("could not fetch asset versions in DaemonRunner", "assetID", asset.ID, "err", err)
				continue
			}

			project, err := DaemonRunner.projectRepository.Read(asset.ProjectID)
			if err != nil {
				slog.Error("could not fetch project in DaemonRunner", "assetID", asset.ID, "err", err)
				continue
			}
			org, err := DaemonRunner.orgRepository.Read(project.OrganizationID)
			if err != nil {
				slog.Error("could not fetch org in DaemonRunner", "assetID", asset.ID, "err", err)
				continue
			}

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

func (runner DaemonRunner) SyncTickets(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer close(out)

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			if !commonint.IsConnectedToThirdPartyIntegration(asset) {
				continue
			}
			for _, assetVersion := range assetWithDetails.assetVersions {
				err := runner.dependencyVulnService.SyncAllIssues(assetWithDetails.org, assetWithDetails.project, asset, assetVersion)
				if err != nil {
					slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", asset.ID, "error", err)
					continue
				}
			}
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) ResolveDifferencesInTicketState(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer close(out)

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			// build new client each time for authentication
			gitlabClient, _, err := runner.integrationAggregate.GetIntegration(shared.GitLabIntegrationID).(*gitlabint.GitlabIntegration).GetClientBasedOnAsset(asset)
			if err != nil {
				slog.Error("could not get gitlab client for asset", "asset", asset.Slug, "err", err)
				continue
			}

			depVulns, err := runner.dependencyVulnRepository.GetAllVulnsByAssetIDWithTicketIDs(nil, asset.ID)
			if err != nil {
				slog.Error("could not get dependency vulns for asset", "assetID", asset.ID, "err", err)
				continue
			}

			// convert the dependency vulns into a list of iids for this asset
			depVulnsIIDs := make([]int, 0, len(depVulns))
			for _, vuln := range depVulns {
				fields := strings.Split(*vuln.TicketID, "/")
				if len(fields) == 1 {
					continue
				}
				// iid is found in the last part of the ticketID
				iid, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					slog.Warn("invalid ticket id", "vulnID", vuln.ID)
					continue
				}
				depVulnsIIDs = append(depVulnsIIDs, iid)
			}

			err = CompareStatesAndResolveDifferences(gitlabClient, asset, depVulnsIIDs)
			if err != nil {
				slog.Error("could not compare ticket states", "err", err)
				continue
			}
			out <- assetWithDetails
		}
	}()
	return out
}

func CompareStatesAndResolveDifferences(client shared.GitlabClientFacade, asset models.Asset, devguardStateIIDs []int) error {
	// if do not have a connection to a repo we do not need to do anything
	if asset.RepositoryID == nil {
		return nil
	}

	//extract information from repository ID
	fields := strings.Split(*asset.RepositoryID, ":")
	if len(fields) == 1 {
		return fmt.Errorf("invalid repository id (%s)", *asset.RepositoryID)
	}
	if fields[0] != "gitlab" {
		slog.Warn("only gitlab is currently supported for this function")
		return nil
	}
	projectID, err := gitlabint.ExtractProjectIDFromRepoID(*asset.RepositoryID)
	if err != nil {
		slog.Error("could not extract projectID from RepoID")
		return err
	}

	issues, err := gitlabint.FetchPaginatedData(func(page int) ([]*gitlab.Issue, *gitlab.Response, error) {
		listIssuesOptions := gitlab.ListProjectIssuesOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 100,
				Page:    page,
			},
			State: utils.Ptr("opened"),
			Labels: &gitlab.LabelOptions{
				"devguard",
			},
		}
		return client.GetProjectIssues(projectID, &listIssuesOptions)
	})
	if err != nil {
		return err
	}

	gitlabIIDs := make([]int, 0, len(issues))
	// only count open tickets created by devguard
	for _, issue := range issues {
		gitlabIIDs = append(gitlabIIDs, issue.IID)
	}

	// compare both states
	comparison := utils.CompareSlices(devguardStateIIDs, gitlabIIDs, func(iid int) int { return iid })
	excessIIDs := comparison.OnlyInB

	// close all excess devguard tickets
	updateOptions := gitlab.UpdateIssueOptions{
		StateEvent: utils.Ptr("close"),
	}
	amountClosed := 0
	for _, iid := range excessIIDs {
		_, _, err = client.EditIssue(context.Background(), projectID, iid, &updateOptions)
		if err != nil {
			slog.Error("could not close issue", "iid", iid)
			continue
		}
		amountClosed++
	}

	slog.Info("successfully resolved ticket state differences", "asset", asset.Slug, "amount closed", amountClosed)
	return nil
}
func (runner DaemonRunner) ScanAsset(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer close(out)

		for assetWithDetails := range input {
			start := time.Now()
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					components, err := runner.componentRepository.LoadComponents(nil, assetVersions[i].Name, assetVersions[i].AssetID, &artifact.ArtifactName)
					if err != nil {
						slog.Error("failed to load components", "error", err)
						continue
					}

					bom, err := runner.assetVersionService.BuildSBOM(asset, assetVersions[i], artifact.ArtifactName, "", components)
					if err != nil {
						slog.Error("error when building SBOM")
						continue
					}
					if len(components) <= 0 {
						continue
					} else {
						_, _, _, err = runner.scanService.ScanNormalizedSBOMWithoutEventHandling(org, project, asset, assetVersions[i], artifact, bom, "system")
					}

					if err != nil {
						slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
						continue
					}

					slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
				}
			}
			monitoring.ScanDaemonDuration.Observe(time.Since(start).Minutes())
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) SyncUpstream(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer close(out)

		for assetWithDetails := range input {
			start := time.Now()
			assetVersions := assetWithDetails.assetVersions
			asset := assetWithDetails.asset
			project := assetWithDetails.project
			org := assetWithDetails.org

			for i := range assetVersions {
				artifacts := assetVersions[i].Artifacts
				for _, artifact := range artifacts {
					rootNodes, err := runner.componentService.FetchInformationSources(&artifact)
					if err != nil {
						slog.Error("failed to fetch root nodes for artifact", "artifact", artifact.ArtifactName, "assetVersion", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
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
						continue
					}

					slog.Info("synced upstream VEX reports for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
					monitoring.UpstreamSyncDuration.Observe(float64(time.Since(start).Minutes()))
				}
			}
		}
	}()
	return out
}

func (runner DaemonRunner) CollectStats(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)
	go func() {
		defer close(out)

		for assetWithDetails := range input {
			for _, assetVersion := range assetWithDetails.assetVersions {
				for _, artifact := range assetVersion.Artifacts {
					start := time.Now()
					if err := runner.statisticsService.UpdateArtifactRiskAggregation(&artifact, artifact.AssetID, utils.OrDefault(artifact.LastHistoryUpdate, time.Now().AddDate(0, -1, 0)), time.Now()); err != nil {
						slog.Error("could not recalculate risk history", "err", err)
						continue
					}

					slog.Info("updated statistics for artifact", "artifactName", artifact.ArtifactName, "assetVersionName", artifact.AssetVersionName, "assetID", artifact.AssetID)
					monitoring.StatisticsUpdateDuration.Observe(time.Since(start).Minutes())
				}
			}
			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) RecalculateRiskForVulnerabilities(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer close(out)

		for assetWithDetails := range input {
			assetVersions := assetWithDetails.assetVersions
			for _, assetVersion := range assetVersions {
				start := time.Now()

				// get all dependencyVulns of the asset
				dependencyVulns, err := runner.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
				if err != nil {
					slog.Error("failed to get dependency vulns for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					continue
				}

				if len(dependencyVulns) == 0 {
					continue
				}

				_, err = runner.dependencyVulnService.RecalculateRawRiskAssessment(nil, "system", dependencyVulns, "System recalculated raw risk assessment", assetVersion.Asset)
				if err != nil {
					slog.Error("failed to recalculate raw risk assessment for asset version", "assetVersionName", assetVersion.Name, "assetID", assetVersion.AssetID, "error", err)
					continue
				}

				monitoring.RecalculateRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
			}

			out <- assetWithDetails
		}
	}()
	return out
}

func (runner DaemonRunner) AutoReopenTickets(input <-chan assetWithProjectAndOrg) <-chan assetWithProjectAndOrg {
	out := make(chan assetWithProjectAndOrg)

	go func() {
		defer close(out)

		for assetWithDetails := range input {
			asset := assetWithDetails.asset
			// convert days to time.Duration
			reopenAfterDuration := time.Duration(*asset.VulnAutoReopenAfterDays) * 24 * time.Hour

			// get all closed/accepted vulnerabilities for the asset version
			vulnerabilities, err := runner.dependencyVulnRepository.GetAllByAssetIDAndState(nil, asset.ID, dtos.VulnStateAccepted, reopenAfterDuration)
			if err != nil {
				slog.Error("failed to get closed/accepted vulnerabilities for asset", "assetID", asset.ID, "error", err)
				continue
			}

			for _, vuln := range vulnerabilities {
				// create a new event for the vulnerability
				event := models.NewReopenedEvent(vuln.ID, dtos.VulnTypeDependencyVuln, "system", fmt.Sprintf("Automatically reopened since the vulnerability was accepted more than %d days ago", *asset.VulnAutoReopenAfterDays), dtos.UpstreamStateInternal)

				if err := runner.dependencyVulnRepository.ApplyAndSave(nil, &vuln, &event); err != nil {
					slog.Error("failed to apply and save vulnerability event", "vulnerabilityID", vuln.ID, "error", err)
				} else {
					slog.Info("reopened vulnerability since it was accepted more than the configured time", "vulnerabilityID", vuln.ID, "assetID", asset.ID, "reopenAfterDays", *asset.VulnAutoReopenAfterDays)
				}
			}
			out <- assetWithDetails
		}
	}()
	return out
}
