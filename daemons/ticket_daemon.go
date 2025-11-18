package daemons

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func SyncTickets(
	db shared.DB,
	thirdPartyIntegrationAggregate shared.IntegrationAggregate,
	dependencyVulnService shared.DependencyVulnService,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
) error {
	start := time.Now()
	defer func() {
		monitoring.SyncTicketDuration.Observe(time.Since(start).Minutes())
	}()

	// Get gitlab integration from the aggregate
	gitlabIntegration := thirdPartyIntegrationAggregate.GetIntegration("gitlab")

	orgs, err := orgRepository.All()
	if err != nil {
		slog.Error("failed to load organizations", "error", err)
		return err
	}

	for _, org := range orgs {
		// get all projects for the org
		projects, err := projectRepository.GetByOrgID(org.ID)
		if err != nil {
			slog.Error("failed to load projects for org", "orgID", org.ID, "error", err)
			continue
		}
		for _, project := range projects {
			// get all assets for the project
			assets, err := assetRepository.GetByProjectID(project.ID)
			if err != nil {
				slog.Error("failed to load assets for project", "projectID", project.ID, "error", err)
				continue
			}
			for _, asset := range assets {
				if !commonint.IsConnectedToThirdPartyIntegration(asset) {
					continue
				}
				// get all asset versions for the asset
				assetVersions, err := assetVersionRepository.GetAssetVersionsByAssetID(db, asset.ID)
				if err != nil {
					slog.Error("failed to load asset versions for asset", "assetID", asset.ID, "error", err)
					continue
				}
				for _, assetVersion := range assetVersions {
					err := dependencyVulnService.SyncAllIssues(org, project, asset, assetVersion)
					if err != nil {
						slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", asset.ID, "error", err)
						continue
					}

				}
				// build new client each time for authentication
				gitlabClient, _, err := gitlabIntegration.(*gitlabint.GitlabIntegration).GetClientBasedOnAsset(asset)
				if err != nil {
					slog.Error("could not get gitlab client for asset", "asset", asset.Slug, "err", err)
					continue
				}
				depVulns, err := dependencyVulnRepository.GetAllVulnsByAssetIDWithTicketIDs(nil, asset.ID)
				if err != nil {
					return err
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
			}
		}
	}
	monitoring.SyncTicketDaemonAmount.Inc()
	return nil
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
