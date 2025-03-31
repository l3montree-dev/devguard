// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package integrations

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
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type githubRepository struct {
	*github.Repository
	GithubAppInstallationID int `json:"githubAppInstallationId"`
}

func (g githubRepository) toRepository() core.Repository {
	return core.Repository{
		ID:    fmt.Sprintf("github:%d:%s", g.GithubAppInstallationID, *g.FullName),
		Label: *g.FullName,
	}
}

// wrapper around the github package - which provides only the methods
// we need
type githubClientFacade interface {
	CreateIssue(ctx context.Context, owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	CreateIssueComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	EditIssue(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	EditIssueLabel(ctx context.Context, owner string, repo string, name string, label *github.Label) (*github.Label, *github.Response, error)
}

type githubIntegration struct {
	githubAppInstallationRepository core.GithubAppInstallationRepository
	externalUserRepository          core.ExternalUserRepository
	dependencyVulnRepository        core.DependencyVulnRepository
	vulnEventRepository             core.VulnEventRepository
	aggregatedVulnRepository        core.VulnRepository
	frontendUrl                     string
	assetRepository                 core.AssetRepository
	assetVersionRepository          core.AssetVersionRepository

	githubClientFactory func(repoId string) (githubClientFacade, error)
}

var _ core.ThirdPartyIntegration = &githubIntegration{}

var NoGithubAppInstallationError = fmt.Errorf("no github app installations found")

func NewGithubIntegration(db core.DB) *githubIntegration {
	githubAppInstallationRepository := repositories.NewGithubAppInstallationRepository(db)

	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)

	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &githubIntegration{
		githubAppInstallationRepository: githubAppInstallationRepository,
		externalUserRepository:          repositories.NewExternalUserRepository(db),
		aggregatedVulnRepository:        aggregatedVulnRepository,
		dependencyVulnRepository:        dependencyVulnRepository,
		vulnEventRepository:             vulnEventRepository,
		frontendUrl:                     frontendUrl,
		assetRepository:                 repositories.NewAssetRepository(db),
		assetVersionRepository:          repositories.NewAssetVersionRepository(db),

		githubClientFactory: func(repoId string) (githubClientFacade, error) {
			return NewGithubClient(installationIdFromRepositoryID(repoId))
		},
	}
}

func (githubIntegration *githubIntegration) GetID() core.IntegrationID {
	return core.GitHubIntegrationID
}

func (githubIntegration *githubIntegration) IntegrationEnabled(ctx core.Context) bool {
	// check if the github app installation exists in the database
	organization := core.GetOrganization(ctx)
	return len(organization.GithubAppInstallations) > 0
}

func (githubIntegration *githubIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	// check if we have integrations
	if !githubIntegration.IntegrationEnabled(ctx) {
		return nil, NoGithubAppInstallationError
	}

	organization := core.GetOrganization(ctx)

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

func (githubIntegration *githubIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}

func (githubIntegration *githubIntegration) GetUsers(org models.Org) []core.User {
	users, err := githubIntegration.externalUserRepository.FindByOrgID(nil, org.ID)
	if err != nil {
		slog.Error("could not get users from github", "err", err)
		return nil
	}

	return utils.Map(users, func(user models.ExternalUser) core.User {
		return core.User{
			ID:        user.ID,
			Name:      user.Username,
			AvatarURL: &user.AvatarURL,
		}
	})
}

func (githubIntegration *githubIntegration) HandleWebhook(ctx core.Context) error {

	req := ctx.Request()
	payload, err := github.ValidatePayload(req, []byte(os.Getenv("GITHUB_WEBHOOK_SECRET")))
	if err != nil {
		slog.Debug("could not validate github webhook", "err", err)
		return nil
	}

	event, err := github.ParseWebHook(github.WebHookType(req), payload)
	if err != nil {
		slog.Error("could not parse github webhook", "err", err)
		return err
	}

	switch event := event.(type) {
	case *github.IssueCommentEvent:
		// check if the issue is a devguard issue
		issueNumber := event.Issue.GetNumber()
		issueID := event.Issue.GetID()
		// check if the user is a bot - we do not want to handle bot comments
		if event.Comment.User.GetType() == "Bot" {
			return nil
		}
		// look for a vuln with such a github ticket id
		vuln, err := githubIntegration.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("github:%d/%d", issueID, issueNumber))
		if err != nil {
			slog.Debug("could not find vuln by ticket id", "err", err, "ticketId", fmt.Sprintf("github:%d/%d", issueID, issueNumber))
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

		// the issue is a devguard issue.
		// lets check what the comment is about
		comment := event.Comment.GetBody()

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

		// create a new event based on the comment
		vulnEvent := createNewVulnEventBasedOnComment(vuln.GetID(), fmt.Sprintf("github:%d", event.Comment.User.GetID()), comment)

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

		// make sure to update the github issue accordingly
		client, err := githubIntegration.githubClientFactory(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not get owner and repo from repository id", "err", err)
			return err
		}

		switch vulnEvent.Type {
		case models.EventTypeAccepted:
			_, _, err = client.EditIssue(ctx.Request().Context(), owner, repo, issueNumber, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(vuln.GetRawRiskAssessment())), "state:accepted"},
			})
			return err
		case models.EventTypeFalsePositive:
			_, _, err = client.EditIssue(ctx.Request().Context(), owner, repo, issueNumber, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(vuln.GetRawRiskAssessment())), "state:false-positive"},
			})
			return err
		case models.EventTypeReopened:
			_, _, err = client.EditIssue(ctx.Request().Context(), owner, repo, issueNumber, &github.IssueRequest{
				State:  github.String("open"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(vuln.GetRawRiskAssessment())), "state:open"},
			})
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

	return ctx.JSON(200, "ok")
}

func (githubIntegration *githubIntegration) WantsToFinishInstallation(ctx core.Context) bool {
	return true
}

func (githubIntegration *githubIntegration) FinishInstallation(ctx core.Context) error {
	// get the installation id from the request
	installationID := ctx.QueryParam("installationId")
	if installationID == "" {
		slog.Error("installationId is required")
		return ctx.JSON(400, "installationId is required")
	}

	// check if the org id does match the current organization id, thus the user has access to the organization
	organization := core.GetOrganization(ctx)
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
	orgId := organization.GetID()
	appInstallation.OrgID = &orgId
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

func installationIdFromRepositoryID(repositoryID string) int {
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
func githubTicketIdToIdAndNumber(id string) (int, int) {
	// format: github:123456789/123
	split := strings.Split(id, "/")

	if len(split) != 2 {
		return 0, 0
	}

	ticketId, err := strconv.Atoi(strings.TrimPrefix(split[0], "github:"))
	if err != nil {
		return 0, 0
	}

	ticketNumber, err := strconv.Atoi(split[1])
	if err != nil {
		return 0, 0
	}

	return ticketId, ticketNumber
}

func (g *githubIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)

		repoId, err := core.GetRepositoryID(event.Ctx)

		if !strings.HasPrefix(repoId, "github:") {
			// this integration only handles github repositories.
			return nil
		}

		assetVersionName := core.GetAssetVersion(event.Ctx).Name
		if err != nil {
			return err
		}
		projectSlug, err := core.GetProjectSlug(event.Ctx)

		if err != nil {
			return err
		}
		dependencyVulnId, err := core.GetVulnID(event.Ctx)
		if err != nil {
			return err
		}
		dependencyVuln, err := g.dependencyVulnRepository.Read(dependencyVulnId)
		if err != nil {
			return err
		}

		orgSlug, err := core.GetOrgSlug(event.Ctx)
		if err != nil {
			return err
		}

		return g.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug)

	case core.VulnEvent:
		ev := event.Event

		asset := core.GetAsset(event.Ctx)
		dependencyVuln, err := g.dependencyVulnRepository.Read(ev.VulnID)

		if err != nil {
			return err
		}

		if dependencyVuln.TicketID == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "github:") || !strings.HasPrefix(*dependencyVuln.TicketID, "github:") {
			// this integration only handles github repositories.
			return nil
		}
		// we create a new ticket in github
		client, err := g.githubClientFactory(repoId)
		if err != nil {
			return err
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
		if err != nil {
			return err
		}

		_, githubTicketNumber := githubTicketIdToIdAndNumber(*dependencyVuln.TicketID)

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
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
			return g.CloseIssue(context.Background(), "accepted", repoId, dependencyVuln)
		case models.EventTypeFalsePositive:

			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			return g.CloseIssue(context.Background(), "false-positive", repoId, dependencyVuln)
		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			return g.ReopenIssue(context.Background(), repoId, dependencyVuln)
		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketNumber, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" commented on the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			return err
		}
	}
	return nil
}

func (g *githubIntegration) CloseIssue(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln) error {
	if !strings.HasPrefix(repoId, "github:") || !strings.HasPrefix(*dependencyVuln.TicketID, "github:") {
		// this integration only handles github repositories.
		return nil
	}

	owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
	if err != nil {
		return err
	}

	client, err := g.githubClientFactory(repoId)
	if err != nil {
		return err
	}

	_, ticketNumber := githubTicketIdToIdAndNumber(*dependencyVuln.TicketID)

	_, _, err = client.EditIssue(ctx, owner, repo, ticketNumber, &github.IssueRequest{
		State:  github.String("closed"),
		Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)), "state:" + state},
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *githubIntegration) ReopenIssue(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln) error {
	if !strings.HasPrefix(repoId, "github:") || !strings.HasPrefix(*dependencyVuln.TicketID, "github:") {
		// this integration only handles github repositories.
		return nil
	}

	owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
	if err != nil {
		return err
	}

	client, err := g.githubClientFactory(repoId)
	if err != nil {
		return err
	}

	_, ticketNumber := githubTicketIdToIdAndNumber(*dependencyVuln.TicketID)

	_, _, err = client.EditIssue(ctx, owner, repo, ticketNumber, &github.IssueRequest{
		State:  github.String("open"),
		Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)), "state:open"},
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *githubIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string) error {

	if !strings.HasPrefix(repoId, "github:") {
		// this integration only handles github repositories.
		return nil
	}

	owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
	if err != nil {
		return err
	}

	// we create a new ticket in github
	client, err := g.githubClientFactory(repoId)
	if err != nil {
		return err
	}

	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug

	issue := &github.IssueRequest{
		Title:  github.String(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.SafeDereference(dependencyVuln.ComponentPurl))),
		Body:   github.String(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, assetSlug, assetVersionName) + "\n\n------\n\n" + "Risk exceeds predefined threshold"),
		Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment))},
	}

	createdIssue, _, err := client.CreateIssue(ctx, owner, repo, issue)
	if err != nil {
		return err
	}

	// todo - we are editing the labels on each call. Actually we only need todo it once
	_, _, err = client.EditIssueLabel(ctx, owner, repo, "severity:"+strings.ToLower(risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)), &github.Label{
		Description: github.String("Severity of the dependencyVuln"),
		Color:       github.String(risk.RiskToColor(*dependencyVuln.RawRiskAssessment)),
	})
	if err != nil {
		slog.Error("could not update label", "err", err)
	}
	_, _, err = client.EditIssueLabel(context.Background(), owner, repo, "devguard", &github.Label{
		Description: github.String("DevGuard"),
		Color:       github.String("182654"),
	})
	if err != nil {
		slog.Error("could not update label", "err", err)
	}

	// save the issue id to the dependencyVuln
	dependencyVuln.TicketID = utils.Ptr(fmt.Sprintf("github:%d/%d", createdIssue.GetID(), createdIssue.GetNumber()))
	dependencyVuln.TicketURL = utils.Ptr(createdIssue.GetHTMLURL())

	// create an event
	vulnEvent := models.NewMitigateEvent(dependencyVuln.ID, "system", "Risk exceeds predefined threshold", map[string]any{
		"ticketId":  *dependencyVuln.TicketID,
		"ticketUrl": createdIssue.GetHTMLURL(),
	})
	// save the dependencyVuln and the event in a transaction
	err = g.dependencyVulnRepository.ApplyAndSave(nil, &dependencyVuln, &vulnEvent)
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
