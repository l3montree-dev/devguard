package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var assetToTicketIIDs map[uuid.UUID][]int

func SyncTickets(db core.DB, thirdPartyIntegrationAggregate core.ThirdPartyIntegration) error {
	start := time.Now()
	defer func() {
		monitoring.SyncTicketDuration.Observe(time.Since(start).Minutes())
	}()

	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)

	dependencyVulnService := vuln.NewService(
		dependencyVulnRepository,
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		thirdPartyIntegrationAggregate,
		repositories.NewAssetVersionRepository(db),
	)

	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db, nil)
	if err != nil {
		panic(err)
	}

	gitlabIntegration := gitlabint.NewGitlabIntegration(db, gitlabOauth2Integrations, casbinRBACProvider, gitlabClientFactory)

	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	orgRepository := repositories.NewOrgRepository(db)

	orgs, err := orgRepository.All()
	if err != nil {
		slog.Error("failed to load organizations", "error", err)
		return err
	}

	// fetch all dependency vulns and map their ticket iid to each the respective asset
	vulns, err := dependencyVulnRepository.All()
	if err != nil {
		return err
	}
	assetToTicketIIDs = make(map[uuid.UUID][]int, len(vulns))

	for _, vuln := range vulns {
		if vuln.TicketID != nil {
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
			// append the iid to previously found ones
			assetToTicketIIDs[vuln.AssetID] = append(assetToTicketIIDs[vuln.AssetID], iid)
		}
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
				if !vuln.IsConnectedToThirdPartyIntegration(asset) {
					continue
				}
				// get all asset versions for the asset
				assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDBByAssetID(db, asset.ID)
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
				gitlabClient, _, err := gitlabIntegration.GetClientBasedOnAsset(asset)
				if err != nil {
					slog.Error("could not get gitlab client for asset", "asset", asset.Slug, "err", err)
					continue
				}
				depVulnsIIDs := assetToTicketIIDs[asset.ID]
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

func CompareStatesAndResolveDifferences(client core.GitlabClientFacade, asset models.Asset, devguardStateIIDs []int) error {
	// if do not have a connection to a repo we do not need to do anything
	if asset.RepositoryID == nil {
		return nil
	}

	//extract projectID
	fields := strings.Split(*asset.RepositoryID, ":")
	if len(fields) == 1 {
		return fmt.Errorf("invalid repository id (%s)", *asset.RepositoryID)
	}
	if fields[0] != "gitlab" {
		slog.Warn("only gitlab is currently supported for this function")
		return nil
	}
	projectID, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return err
	}

	issues, err := client.GetProjectIssues(projectID)
	if err != nil {
		return err
	}

	gitlabIIDs := make([]int, 0, len(issues))
	// only count open tickets created by devguard
	for _, issue := range issues {
		if issue.State == "opened" && slices.Contains(issue.Labels, "devguard") {
			gitlabIIDs = append(gitlabIIDs, issue.IID)
		}
	}

	// compare both states
	comparison := utils.CompareSlices(devguardStateIIDs, gitlabIIDs, func(iid int) int { return iid })
	excessIIDs := comparison.OnlyInB

	// close all excess devguard tickets
	opt := gitlab.UpdateIssueOptions{
		StateEvent: utils.Ptr("close"),
	}
	amountClosed := 0
	for _, iid := range excessIIDs {
		_, _, err = client.EditIssue(context.Background(), projectID, iid, &opt)
		if err != nil {
			slog.Error("could not close issue", "iid", iid)
			continue
		}
		amountClosed++
	}

	slog.Info("successfully resolved ticket state differences", "asset", asset.Slug, "amount closed", amountClosed)
	return nil
}
