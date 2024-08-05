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
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/internal/core"
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

type githubAppInstallationRepository interface {
	Save(tx core.DB, model *models.GithubAppInstallation) error
	Read(installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error)
	Delete(tx core.DB, installationID int) error
}

type flawRepository interface {
	Read(id string) (models.Flaw, error)
	Save(db core.DB, flaw *models.Flaw) error
	Transaction(fn func(tx core.DB) error) error
}

type flawEventRepository interface {
	Save(db core.DB, event *models.FlawEvent) error
}

type githubIntegration struct {
	githubAppInstallationRepository githubAppInstallationRepository
	flawRepository                  flawRepository
	flawEventRepository             flawEventRepository
	frontendUrl                     string
}

var _ core.ThirdPartyIntegration = &githubIntegration{}

var NoGithubAppInstallationError = fmt.Errorf("no github app installations found")

func NewGithubIntegration(db core.DB) *githubIntegration {
	githubAppInstallationRepository := repositories.NewGithubAppInstallationRepository(db)

	flawRepository := repositories.NewFlawRepository(db)
	flawEventRepository := repositories.NewFlawEventRepository(db)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &githubIntegration{
		githubAppInstallationRepository: githubAppInstallationRepository,
		flawRepository:                  flawRepository,
		flawEventRepository:             flawEventRepository,

		frontendUrl: frontendUrl,
	}
}

func (githubIntegration *githubIntegration) IntegrationEnabled(ctx core.Context) bool {
	// check if the github app installation exists in the database
	tenant := core.GetTenant(ctx)
	return tenant.GithubAppInstallations != nil && len(tenant.GithubAppInstallations) > 0
}

func (githubIntegration *githubIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	// check if we have integrations
	if !githubIntegration.IntegrationEnabled(ctx) {
		return nil, NoGithubAppInstallationError
	}

	tenant := core.GetTenant(ctx)

	repos := []core.Repository{}
	// check if a github integration exists on that org
	if tenant.GithubAppInstallations != nil {
		// get the github integration
		githubClient, err := newGithubBatchClient(tenant.GithubAppInstallations)
		if err != nil {
			return nil, err
		}

		// get the repositories
		r, err := githubClient.ListRepositories()
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

func (githubIntegration *githubIntegration) HandleWebhook(ctx core.Context) error {
	payload, err := github.ValidatePayload(ctx.Request(), []byte(os.Getenv("GITHUB_WEBHOOK_SECRET")))
	if err != nil {
		slog.Error("could not validate github webhook", "err", err)
		return err
	}

	event, err := github.ParseWebHook(github.WebHookType(ctx.Request()), payload)
	if err != nil {
		slog.Error("could not parse github webhook", "err", err)
		return err
	}

	switch event := event.(type) {
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
	tenant := core.GetTenant(ctx)
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
	if appInstallation.OrgID != nil && *appInstallation.OrgID != tenant.GetID() {
		slog.Error("github app installation already associated with an organization")
		return ctx.JSON(400, "github app installation already associated with an organization")
	} else if appInstallation.OrgID != nil && *appInstallation.OrgID == tenant.GetID() {
		slog.Info("github app installation already associated with the organization")
		return ctx.JSON(200, "ok")
	}

	// add the organization id to the installation
	orgId := tenant.GetID()
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

func (g *githubIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)
		flawId, err := core.GetFlawID(event.Ctx)
		if err != nil {
			return err
		}

		flaw, err := g.flawRepository.Read(flawId)
		if err != nil {
			return err
		}

		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "github:") {
			// this integration only handles github repositories.
			return nil
		}
		// we create a new ticket in github
		client, err := NewGithubClient(installationIdFromRepositoryID(repoId))
		if err != nil {
			return err
		}
		riskMetrics, vector := risk.RiskCalculation(*flaw.CVE, core.GetEnvironmentalFromAsset(asset))

		exp := risk.Explain(flaw, asset, vector, riskMetrics)
		// print json stringify to the console
		orgSlug, _ := core.GetOrgSlug(event.Ctx)
		projectSlug, _ := core.GetProjectSlug(event.Ctx)
		assetSlug, _ := core.GetAssetSlug(event.Ctx)

		// create a new issue
		issue := &github.IssueRequest{
			Title:  github.String(flaw.CVEID),
			Body:   github.String(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, assetSlug)),
			Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment))},
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
		if err != nil {
			return err
		}

		createdIssue, _, err := client.Issues.Create(context.Background(), owner, repo, issue)
		if err != nil {
			return err
		}

		_, _, err = client.Issues.EditLabel(context.Background(), owner, repo, "severity:"+strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), &github.Label{
			Description: github.String("Severity of the flaw"),
			Color:       github.String(risk.RiskToColor(*flaw.RawRiskAssessment)),
		})
		if err != nil {
			slog.Error("could not update label", "err", err)
		}
		_, _, err = client.Issues.EditLabel(context.Background(), owner, repo, "devguard", &github.Label{
			Description: github.String("DevGuard"),
			Color:       github.String("182654"),
		})
		if err != nil {
			slog.Error("could not update label", "err", err)
		}

		// save the issue id to the flaw
		flaw.TicketID = utils.Ptr(fmt.Sprintf("github:%d", createdIssue.GetID()))
		session := core.GetSession(event.Ctx)
		userID := session.GetUserID()
		// create an event
		flawEvent := models.NewMitigateEvent(flaw.ID, userID, event.Ctx.Param("justification"), map[string]any{
			"ticketId": flaw.TicketID,
			"url":      createdIssue.GetHTMLURL(),
		})
		// save the flaw and the event in a transaction
		err = g.flawRepository.Transaction(func(tx core.DB) error {
			err := g.flawRepository.Save(tx, &flaw)
			if err != nil {
				return err
			}
			err = g.flawEventRepository.Save(tx, &flawEvent)
			if err != nil {
				return err
			}
			return nil
		})
		// if an error did happen, delete the issue from github
		if err != nil {
			_, _, err := client.Issues.Edit(context.TODO(), owner, repo, createdIssue.GetNumber(), &github.IssueRequest{
				State: github.String("closed"),
			})
			if err != nil {
				slog.Error("could not delete issue", "err", err)
			}
			return err
		}
		return nil

	case core.FlawDetectedEvent:
		return nil
	}
	return nil
}
