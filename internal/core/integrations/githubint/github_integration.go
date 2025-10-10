// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package githubint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type githubRepository struct {
	*github.Repository
	GithubAppInstallationID int `json:"githubAppInstallationId"`
}

func (githubIntegration githubRepository) toRepository() core.Repository {
	var image string
	if githubIntegration.Organization != nil && githubIntegration.Organization.AvatarURL != nil {
		image = utils.SafeDereference(githubIntegration.Organization.AvatarURL)
	} else if githubIntegration.Owner != nil && githubIntegration.Owner.AvatarURL != nil {
		image = utils.SafeDereference(githubIntegration.Owner.AvatarURL)
	}
	return core.Repository{
		ID:          fmt.Sprintf("github:%d:%s", githubIntegration.GithubAppInstallationID, utils.SafeDereference(githubIntegration.FullName)),
		Label:       utils.SafeDereference(githubIntegration.FullName),
		Image:       image,
		Description: utils.SafeDereference(githubIntegration.Description),
	}
}

type GithubIntegration struct {
	githubAppInstallationRepository core.GithubAppInstallationRepository
	externalUserRepository          core.ExternalUserRepository
	dependencyVulnRepository        core.DependencyVulnRepository
	firstPartyVulnRepository        core.FirstPartyVulnRepository
	vulnEventRepository             core.VulnEventRepository
	aggregatedVulnRepository        core.VulnRepository
	frontendURL                     string
	assetRepository                 core.AssetRepository
	assetVersionRepository          core.AssetVersionRepository
	componentRepository             core.ComponentRepository
	licenseRiskRepository           core.LicenseRiskRepository

	orgRepository       core.OrganizationRepository
	projectRepository   core.ProjectRepository
	githubClientFactory func(repoID string) (githubClientFacade, error)
	statisticsService   core.StatisticsService
}

var _ core.ThirdPartyIntegration = &GithubIntegration{}

var ErrNoGithubAppInstallation = fmt.Errorf("no github app installations found")

func NewGithubIntegration(db core.DB) *GithubIntegration {
	githubAppInstallationRepository := repositories.NewGithubAppInstallationRepository(db)

	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	licenseRiskRepository := repositories.NewLicenseRiskRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	assetRiskAggregationRepository := repositories.NewArtifactRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	releaseRepository := repositories.NewReleaseRepository(db)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, releaseRepository)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		panic("FRONTEND_URL is not set")
	}

	return &GithubIntegration{
		githubAppInstallationRepository: githubAppInstallationRepository,
		externalUserRepository:          repositories.NewExternalUserRepository(db),
		aggregatedVulnRepository:        aggregatedVulnRepository,
		dependencyVulnRepository:        dependencyVulnRepository,
		firstPartyVulnRepository:        firstPartyVulnRepository,
		vulnEventRepository:             vulnEventRepository,
		frontendURL:                     frontendURL,
		assetRepository:                 repositories.NewAssetRepository(db),
		assetVersionRepository:          assetVersionRepository,
		componentRepository:             componentRepository,
		projectRepository:               projectRepository,
		orgRepository:                   orgRepository,
		licenseRiskRepository:           licenseRiskRepository,
		statisticsService:               statisticsService,

		githubClientFactory: func(repoID string) (githubClientFacade, error) {
			return NewGithubClient(installationIDFromRepositoryID(repoID))
		},
	}
}

func (githubIntegration *GithubIntegration) CreateLabels(ctx context.Context, asset models.Asset) error {
	return nil
}

func (githubIntegration *GithubIntegration) GetID() core.IntegrationID {
	return core.GitHubIntegrationID
}

func (githubIntegration *GithubIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []core.Role, error) {
	// currently not supported.
	return nil, nil, nil
}

func (githubIntegration *GithubIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []core.Role, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (githubIntegration *GithubIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// currently not supported.
	return nil, fmt.Errorf("not implemented")
}

func (githubIntegration *GithubIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	return false, nil
}

func (githubIntegration *GithubIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (core.Role, error) {
	// currently not supported.
	return core.RoleGuest, fmt.Errorf("not implemented")
}

func (githubIntegration *GithubIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (core.Role, error) {
	// currently not supported.
	return core.RoleGuest, fmt.Errorf("not implemented")
}

func (githubIntegration *GithubIntegration) GetOrg(ctx context.Context, userID string, providerID string, groupID string) (models.Org, error) {
	// currently not supported.
	return models.Org{}, fmt.Errorf("not implemented")
}

func (githubIntegration *GithubIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	if !core.HasOrganization(ctx) {
		// github integration is connected to an organization not a user
		// thus we NEED an organization for this
		return []core.Repository{}, nil
	}

	organization := core.GetOrg(ctx)

	repos := []core.Repository{}
	// check if a github integration exists on that org
	if organization.GithubAppInstallations != nil {
		// get the github integration
		githubClient, err := newGithubBatchClient(organization.GithubAppInstallations)
		if err != nil {
			return nil, err
		}

		// get the repositories
		r, err := githubClient.ListRepositories(ctx.QueryParam("search"))
		if err != nil {
			return nil, err
		}

		repos = append(repos, utils.Map(r, func(repo githubRepository) core.Repository {
			return repo.toRepository()
		})...)
		return repos, nil
	}

	return []core.Repository{}, nil
}

func (githubIntegration *GithubIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}

func (githubIntegration *GithubIntegration) HandleWebhook(ctx core.Context) error {
	req := ctx.Request()
	payload, err := github.ValidatePayload(req, []byte(os.Getenv("GITHUB_WEBHOOK_SECRET")))
	if err != nil {
		return nil
	}

	event, err := github.ParseWebHook(github.WebHookType(req), payload)
	if err != nil {
		return nil
	}
	var vuln models.Vuln
	doUpdateArtifactRiskHistory := false

	switch event := event.(type) {
	case *github.IssuesEvent:
		if event.Sender.GetType() == "Bot" {
			return nil
		}
		// check if the issue is a devguard issue
		issueNumber := event.Issue.GetNumber()
		issueID := event.Issue.GetID()

		// look for a vuln with such a github ticket id
		vuln, err := githubIntegration.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("github:%d/%d", issueID, issueNumber))
		if err != nil {
			slog.Debug("could not find vuln by ticket id", "err", err, "ticketID", fmt.Sprintf("github:%d/%d", issueID, issueNumber))
			return nil
		}
		action := *event.Action

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := githubIntegration.aggregatedVulnRepository.GetOrgFromVuln(vuln)
			if err != nil {
				slog.Error("could not get org from vuln id", "err", err)
				return
			}
			// save the user in the database
			user := models.ExternalUser{
				ID:        fmt.Sprintf("github:%d", event.Issue.User.GetID()),
				Username:  event.Sender.GetLogin(),
				AvatarURL: *event.Sender.AvatarURL,
			}

			err = githubIntegration.externalUserRepository.Save(nil, &user)
			if err != nil {
				slog.Error("could not save github user", "err", err)
				return
			}

			if err = githubIntegration.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
				slog.Error("could not append user to organization", "err", err)
			}
		}()

		switch action {
		case "closed":
			vulnEvent := models.NewAcceptedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("github:%d", event.Sender.GetID()), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the github ticket.", event.Sender.GetLogin()), 0)

			err := githubIntegration.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save vuln and event", "err", err)
			}
			doUpdateArtifactRiskHistory = true

		case "reopened":
			vulnEvent := models.NewReopenedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("github:%d", event.Sender.GetID()), fmt.Sprintf("This Vulnerability is reopened by %s", event.Sender.GetLogin()), 0)

			err := githubIntegration.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save vuln and event", "err", err)
			}
			doUpdateArtifactRiskHistory = true

		case "deleted":
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("github:%d", event.Sender.GetID()), fmt.Sprintf("This Vulnerability is marked as a false positive by %s, due to the deletion of the github ticket.", event.Sender.GetLogin()), models.VulnerableCodeNotInExecutePath, vuln.GetScannerIDsOrArtifactNames(), 0)

			err := githubIntegration.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save vuln and event", "err", err)
			}
			doUpdateArtifactRiskHistory = true
		}
	case *github.IssueCommentEvent:
		// check if the issue is a devguard issues
		issueNumber := event.Issue.GetNumber()
		issueID := event.Issue.GetID()
		// check if the user is a bot - we do not want to handle bot comments
		if event.Comment.User.GetType() == "Bot" {
			return nil
		}
		// look for a vuln with such a github ticket id
		vuln, err = githubIntegration.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("github:%d/%d", issueID, issueNumber))
		if err != nil {
			slog.Debug("could not find vuln by ticket id", "err", err, "ticketID", fmt.Sprintf("github:%d/%d", issueID, issueNumber))
			return nil
		}

		// get the asset
		assetVersion, err := githubIntegration.assetVersionRepository.Read(vuln.GetAssetVersionName(), vuln.GetAssetID())
		if err != nil {
			slog.Error("could not read asset version", "err", err)
			return err
		}

		asset, err := githubIntegration.assetRepository.Read(assetVersion.AssetID)
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}

		client, err := githubIntegration.githubClientFactory(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		isAuthorized, err := isGithubUserAuthorized(event, client)
		if err != nil {
			return err
		}
		if !isAuthorized {
			slog.Info("user not authorized for commands")
			return ctx.JSON(200, "ok")
		}

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := githubIntegration.aggregatedVulnRepository.GetOrgFromVuln(vuln)
			if err != nil {
				slog.Error("could not get org from vuln id", "err", err)
				return
			}
			// save the user in the database
			user := models.ExternalUser{
				ID:        fmt.Sprintf("github:%d", event.Comment.User.GetID()),
				Username:  event.Comment.User.GetLogin(),
				AvatarURL: event.Comment.User.GetAvatarURL(),
			}

			err = githubIntegration.externalUserRepository.Save(nil, &user)
			if err != nil {
				slog.Error("could not save github user", "err", err)
				return
			}

			if err = githubIntegration.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
				slog.Error("could not append user to organization", "err", err)
			}
		}()

		// the issue is a devguard issue.
		// lets check what the comment is about
		comment := event.Comment.GetBody()

		// create a new event based on the comment
		vulnEvent := commonint.CreateNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("github:%d", event.Comment.User.GetID()), comment, vuln.GetScannerIDsOrArtifactNames())

		vulnEvent.Apply(vuln)
		// save the vuln and the event in a transaction
		err = githubIntegration.aggregatedVulnRepository.Transaction(func(tx core.DB) error {
			err := githubIntegration.aggregatedVulnRepository.Save(tx, &vuln)
			if err != nil {
				return err
			}
			err = githubIntegration.vulnEventRepository.Save(tx, &vulnEvent)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			slog.Error("could not save the vulnerability and the event", "err", err)
			return err
		}

		if vulnEvent.Type == models.EventTypeAccepted || vulnEvent.Type == models.EventTypeFalsePositive || vulnEvent.Type == models.EventTypeReopened {
			doUpdateArtifactRiskHistory = true
		}

		err = githubIntegration.UpdateIssue(ctx.Request().Context(), asset, assetVersion.Slug, vuln)

		if err != nil {
			slog.Error("could not update issue", "err", err)
			return err
		}

	case *github.InstallationEvent:
		// check what type of action is being performed
		switch *event.Action {
		case "created":
			slog.Info("new app installation", "installationId", *event.Installation.ID, "senderId", *event.Sender.ID)

			githubAppInstallation := models.GithubAppInstallation{
				InstallationID:                         int(*event.Installation.ID),
				InstallationCreatedWebhookReceivedTime: time.Now(),
				SettingsURL:                            *event.Installation.HTMLURL,
				TargetType:                             *event.Installation.TargetType,
				TargetLogin:                            *event.Installation.Account.Login,
				TargetAvatarURL:                        *event.Installation.Account.AvatarURL,
			}
			// save the new installation to the database
			err := githubIntegration.githubAppInstallationRepository.Save(nil, &githubAppInstallation)
			if err != nil {
				slog.Error("could not save github app installation", "err", err)
				return err
			}
		case "deleted":
			slog.Info("app installation deleted", "installationId", *event.Installation.ID, "senderId", *event.Sender.ID)
			// delete the installation from the database
			err := githubIntegration.githubAppInstallationRepository.Delete(nil, int(*event.Installation.ID))
			if err != nil {
				slog.Error("could not delete github app installation", "err", err)
				return err
			}
		}

	}

	if doUpdateArtifactRiskHistory && vuln != nil {
		artifacts := vuln.GetArtifacts()
		for _, artifact := range artifacts {
			if err := githubIntegration.statisticsService.UpdateArtifactRiskAggregation(&artifact, vuln.GetAssetID(), time.Now(), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
			}
		}
	}

	return ctx.JSON(200, "ok")
}

// function to check if a user is allowed to use commands like /accept, more checks can be added later
func isGithubUserAuthorized(event *github.IssueCommentEvent, client githubClientFacade) (bool, error) {
	if event == nil || event.Sender == nil || event.Repo == nil || event.Repo.Owner == nil {
		slog.Error("missing event data, could not resolve if user is authorized")
		return false, fmt.Errorf("missing event data, could not resolve if user is authorized")
	}
	return client.IsCollaboratorInRepository(context.TODO(), *event.Repo.Owner.Login, *event.Repo.Name, *event.Sender.ID, nil)
}

func (githubIntegration *GithubIntegration) WantsToFinishInstallation(ctx core.Context) bool {
	return true
}

func (githubIntegration *GithubIntegration) FinishInstallation(ctx core.Context) error {
	// get the installation id from the request
	installationID := ctx.QueryParam("installationId")
	if installationID == "" {
		slog.Error("installationId is required")
		return ctx.JSON(400, "installationId is required")
	}

	// check if the org id does match the current organization id, thus the user has access to the organization
	organization := core.GetOrg(ctx)
	// convert the installation id to an integer
	installationIDInt, err := strconv.Atoi(installationID)
	if err != nil {
		slog.Error("could not convert installationId to int", "err", err)
		return ctx.JSON(400, "could not convert installationId to int")
	}

	// check if the installation id exists in the database
	appInstallation, err := githubIntegration.githubAppInstallationRepository.Read(installationIDInt)
	if err != nil {
		slog.Error("could not read github app installation", "err", err)
		return ctx.JSON(400, "could not read github app installation")
	}

	// check if app installation is already associated with an organization
	if appInstallation.OrgID != nil && *appInstallation.OrgID != organization.GetID() {
		slog.Error("github app installation already associated with an organization")
		return ctx.JSON(400, "github app installation already associated with an organization")
	} else if appInstallation.OrgID != nil && *appInstallation.OrgID == organization.GetID() {
		slog.Info("github app installation already associated with the organization")
		return ctx.JSON(200, "ok")
	}

	// add the organization id to the installation
	orgID := organization.GetID()
	appInstallation.OrgID = &orgID
	// save the installation to the database
	err = githubIntegration.githubAppInstallationRepository.Save(nil, &appInstallation)
	if err != nil {
		slog.Error("could not save github app installation", "err", err)
		return ctx.JSON(400, "could not save github app installation")
	}

	// update the installation with the webhook received time
	// save the installation to the database
	return ctx.JSON(200, "ok")
}

func installationIDFromRepositoryID(repositoryID string) int {
	split := strings.Split(repositoryID, ":")
	if len(split) != 3 {
		return 0
	}
	installationID, err := strconv.Atoi(split[1])
	if err != nil {
		return 0
	}
	return installationID
}

func ownerAndRepoFromRepositoryID(repositoryID string) (string, string, error) {
	split := strings.Split(repositoryID, ":")
	if len(split) != 3 {
		return "", "", fmt.Errorf("could not split repository id")
	}

	split = strings.Split(split[2], "/")
	if len(split) != 2 {
		return "", "", fmt.Errorf("could not split repository id")
	}

	return split[0], split[1], nil
}

// the first return value is the global ticket id - a huge number, the second is the ticket number - like #386 you find in github links
func githubTicketIDToIDAndNumber(id string) (int, int) {
	// format: github:123456789/123
	split := strings.Split(id, "/")

	if len(split) != 2 {
		return 0, 0
	}

	ticketID, err := strconv.Atoi(strings.TrimPrefix(split[0], "github:"))
	if err != nil {
		return 0, 0
	}

	ticketNumber, err := strconv.Atoi(split[1])
	if err != nil {
		return 0, 0
	}

	return ticketID, ticketNumber
}

func (githubIntegration *GithubIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)

		repoID, err := core.GetRepositoryID(&asset)

		if !strings.HasPrefix(repoID, "github:") {
			// this integration only handles github repositories.
			return nil
		}

		assetVersionSlug := core.GetAssetVersion(event.Ctx).Slug
		if err != nil {
			return err
		}
		projectSlug, err := core.GetProjectSlug(event.Ctx)

		if err != nil {
			return err
		}

		vulnID, vulnType, err := core.GetVulnID(event.Ctx)

		if err != nil {
			return err
		}

		var vuln models.Vuln

		switch vulnType {
		case models.VulnTypeDependencyVuln:
			// we have a dependency vuln
			v, err := githubIntegration.dependencyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := githubIntegration.firstPartyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeLicenseRisk:
			v, err := githubIntegration.licenseRiskRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		orgSlug, err := core.GetOrgSlug(event.Ctx)
		if err != nil {
			return err
		}

		session := core.GetSession(event.Ctx)

		return githubIntegration.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionSlug, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
	case core.VulnEvent:
		ev := event.Event

		asset := core.GetAsset(event.Ctx)
		assetVersionSlug := core.GetAssetVersion(event.Ctx).Slug

		vulnType := ev.VulnType

		var vuln models.Vuln
		switch vulnType {
		case models.VulnTypeDependencyVuln:
			v, err := githubIntegration.dependencyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := githubIntegration.firstPartyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeLicenseRisk:
			v, err := githubIntegration.licenseRiskRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		if vuln.GetTicketID() == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		repoID := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoID, "github:") || !strings.HasPrefix(*vuln.GetTicketID(), "github:") {
			// this integration only handles github repositories.
			return nil
		}
		// we create a new ticket in github
		client, err := githubIntegration.githubClientFactory(repoID)
		if err != nil {
			return err
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(repoID)
		if err != nil {
			return err
		}

		_, githubTicketNumber := githubTicketIDToIDAndNumber(*vuln.GetTicketID())

		members, err := org.FetchMembersOfOrganization(event.Ctx)
		if err != nil {
			return err
		}

		// find the member which created the event
		member, ok := utils.Find(
			members,
			func(member core.User) bool {
				return member.ID == ev.UserID
			},
		)
		if !ok {
			member = core.User{
				Name: "unknown",
			}
		}

		switch ev.Type {
		case models.EventTypeAccepted:
			// if a dependencyVuln gets accepted, we close the issue and create a comment with that justification
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("### %s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case models.EventTypeFalsePositive:

			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("### %s\n----\n%s", member.Name+" marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("### %s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf(" %s\n \n%s", utils.SafeDereference(ev.Justification), "*Sent from "+member.Name+" using DevGuard*")),
			})
			return err
		}
		return githubIntegration.UpdateIssue(context.Background(), asset, assetVersionSlug, vuln)
	}
	return nil
}

func (githubIntegration *GithubIntegration) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "github:") {
		// this integration only handles github repositories.
		return nil
	}

	owner, repo, err := ownerAndRepoFromRepositoryID(repoID)
	if err != nil {
		return err
	}

	client, err := githubIntegration.githubClientFactory(repoID)
	if err != nil {
		return err
	}

	project, err := githubIntegration.projectRepository.GetProjectByAssetID(asset.ID)
	if err != nil {
		slog.Error("could not get project by asset id", "err", err)
		return err
	}

	org, err := githubIntegration.orgRepository.Read(project.OrganizationID)
	if err != nil {
		slog.Error("could not get org by id", "err", err)
		return err
	}

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		err = githubIntegration.updateDependencyVulnTicket(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug, owner, repo)
	case *models.FirstPartyVuln:
		err = githubIntegration.updateFirstPartyVulnTicket(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug, owner, repo)
	}

	if err != nil {
		//check if err is 404 - if so, we can not reopen the issue
		if err.Error() == "404 Not Found" {
			// we can not reopen the issue - it is deleted
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), "system", "This Vulnerability is marked as a false positive due to deletion", models.VulnerableCodeNotInExecutePath, vuln.GetScannerIDsOrArtifactNames(), 0)
			// save the event
			err = githubIntegration.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			return nil
		}
		return err
	}

	return nil
}

func (githubIntegration *GithubIntegration) updateFirstPartyVulnTicket(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client githubClientFacade, assetVersionSlug, orgSlug, projectSlug, owner, repo string) error {
	_, ticketNumber := githubTicketIDToIDAndNumber(*firstPartyVuln.TicketID)

	expectedIssueState := "closed"
	if firstPartyVuln.State == models.VulnStateOpen {
		expectedIssueState = "open"
	}

	labels := commonint.GetLabels(firstPartyVuln)
	issueRequest := &github.IssueRequest{
		State:  github.String(expectedIssueState),
		Title:  github.String(firstPartyVuln.Title()),
		Body:   github.String(firstPartyVuln.RenderMarkdown(githubIntegration.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		Labels: &labels,
	}

	_, _, err := client.EditIssue(ctx, owner, repo, ticketNumber, issueRequest)
	return err
}

func (githubIntegration *GithubIntegration) updateDependencyVulnTicket(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client githubClientFacade, assetVersionSlug, orgSlug, projectSlug, owner, repo string) error {

	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	componentTree, err := commonint.RenderPathToComponent(githubIntegration.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.Artifacts, exp.ComponentPurl)
	if err != nil {
		return err
	}

	_, ticketNumber := githubTicketIDToIDAndNumber(*dependencyVuln.TicketID)

	expectedIssueState := vuln.GetExpectedIssueState(asset, dependencyVuln)

	labels := commonint.GetLabels(dependencyVuln)
	issueRequest := &github.IssueRequest{
		State:  github.String(expectedIssueState.ToGithub()),
		Title:  github.String(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Body:   github.String(exp.Markdown(githubIntegration.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug, componentTree)),
		Labels: &labels,
	}

	_, _, err = client.EditIssue(ctx, owner, repo, ticketNumber, issueRequest)
	return err
}

func (githubIntegration *GithubIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "github:") {
		// this integration only handles github repositories.
		return nil
	}

	owner, repo, err := ownerAndRepoFromRepositoryID(repoID)
	if err != nil {
		return err
	}

	// we create a new ticket in github
	client, err := githubIntegration.githubClientFactory(repoID)
	if err != nil {
		return err
	}

	var createdIssue *github.Issue

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = githubIntegration.createDependencyVulnIssue(ctx, v, asset, client, assetVersionSlug, justification, orgSlug, projectSlug, owner, repo)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = githubIntegration.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionSlug, justification, orgSlug, projectSlug, owner, repo)
		if err != nil {
			return err
		}
	}

	// save the issue id to the dependencyVuln
	vuln.SetTicketID(fmt.Sprintf("github:%d/%d", createdIssue.GetID(), createdIssue.GetNumber()))
	vuln.SetTicketURL(createdIssue.GetHTMLURL())
	vuln.SetManualTicketCreation(userID != "system")

	// create an event
	vulnEvent := models.NewMitigateEvent(vuln.GetID(), vuln.GetType(), userID, justification, map[string]any{
		"ticketId":  vuln.GetTicketID(),
		"ticketUrl": vuln.GetTicketURL(),
	})
	// save the dependencyVuln and the event in a transaction
	err = githubIntegration.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
	// if an error did happen, delete the issue from github
	if err != nil {
		_, _, err := client.EditIssue(context.TODO(), owner, repo, createdIssue.GetNumber(), &github.IssueRequest{
			State: github.String("closed"),
		})
		if err != nil {
			slog.Error("could not delete issue", "err", err)
		}
		return err
	}

	return nil
}

func (githubIntegration *GithubIntegration) createFirstPartyVulnIssue(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client githubClientFacade, assetVersionSlug, justification, orgSlug, projectSlug, owner, repo string) (*github.Issue, error) {
	labels := commonint.GetLabels(firstPartyVuln)
	issue := &github.IssueRequest{
		Title:  github.String(firstPartyVuln.Title()),
		Body:   github.String(firstPartyVuln.RenderMarkdown(githubIntegration.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		Labels: &labels,
	}

	createdIssue, _, err := client.CreateIssue(ctx, owner, repo, issue)
	if err != nil {
		return nil, err
	}

	_, _, err = client.EditIssueLabel(ctx, owner, repo, "devguard", &github.Label{
		Description: github.String("DevGuard"),
		Color:       github.String("182654"),
	})
	if err != nil {
		slog.Error("could not update label", "err", err)
	}

	// create comment with the justification
	_, _, err = client.CreateIssueComment(ctx, owner, repo, createdIssue.GetNumber(), &github.IssueComment{
		Body: github.String(justification),
	})
	if err != nil {
		slog.Error("could not create issue comment", "err", err)
	}

	return createdIssue, nil
}

func (githubIntegration *GithubIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client githubClientFacade, assetVersionSlug, justification, orgSlug, projectSlug, owner, repo string) (*github.Issue, error) {
	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug
	labels := commonint.GetLabels(dependencyVuln)
	componentTree, err := commonint.RenderPathToComponent(githubIntegration.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.Artifacts, exp.ComponentPurl)
	if err != nil {
		return nil, err
	}

	issue := &github.IssueRequest{
		Title: github.String(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID),
			utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Body:   github.String(exp.Markdown(githubIntegration.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, componentTree)),
		Labels: &labels,
	}

	createdIssue, _, err := client.CreateIssue(ctx, owner, repo, issue)
	if err != nil {
		return nil, err
	}

	riskSeverity, err := risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)
	if err == nil {
		// todo - we are editing the labels on each call. Actually we only need todo it once
		_, _, err = client.EditIssueLabel(ctx, owner, repo, "risk:"+strings.ToLower(riskSeverity), &github.Label{
			Description: github.String("Calculated risk of the vulnerability (based on CVSS, EPSS, and other factors)"),
			Color:       github.String(risk.RiskToColor(*dependencyVuln.RawRiskAssessment)),
		})

		if err != nil {
			slog.Error("could not update label", "err", err)
		}
	}

	cvssSeverity, err := risk.RiskToSeverity(float64(dependencyVuln.CVE.CVSS))
	if err == nil {
		_, _, err = client.EditIssueLabel(ctx, owner, repo, "cvss-severity:"+strings.ToLower(cvssSeverity), &github.Label{
			Description: github.String("CVSS severity of the vulnerability"),
			Color:       github.String(risk.RiskToColor(float64(dependencyVuln.CVE.CVSS))),
		})

		if err != nil {
			slog.Error("could not update label", "err", err)
		}
	}

	if err != nil {
		slog.Error("could not update label", "err", err)
	}
	_, _, err = client.EditIssueLabel(ctx, owner, repo, "devguard", &github.Label{
		Description: github.String("DevGuard"),
		Color:       github.String("182654"),
	})
	if err != nil {
		slog.Error("could not update label", "err", err)
	}

	// create comment with the justification

	_, _, err = client.CreateIssueComment(ctx, owner, repo, createdIssue.GetNumber(), &github.IssueComment{
		Body: github.String(justification),
	})
	if err != nil {
		slog.Error("could not create issue comment", "err", err)
	}

	return createdIssue, nil
}
