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
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/utils"
)

type githubAppInstallationRepository interface {
	Save(tx core.DB, model *models.GithubAppInstallation) error
	Read(installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error)
}

type githubIntegration struct {
	githubAppId                     int64
	githubAppInstallationRepository githubAppInstallationRepository
}

func NewGithubIntegration(githubInstallationRepository githubAppInstallationRepository) *githubIntegration {
	appId := os.Getenv("GITHUB_APP_ID")
	if appId == "" {
		panic("GITHUB_APP_ID is not set")
	}
	appIdInt, err := strconv.Atoi(appId)
	if err != nil {
		panic("Could not convert GITHUB_APP_ID to int: " + appId + ", " + err.Error())
	}

	return &githubIntegration{
		githubAppId:                     int64(appIdInt),
		githubAppInstallationRepository: githubInstallationRepository,
	}
}

var githubNotConnectedError = fmt.Errorf("github not connected")

type orgGithubClient struct {
	clients []*github.Client
}

func (orgGithubClient *orgGithubClient) ListRepositories() ([]*github.Repository, error) {
	wg := utils.ErrGroup[[]*github.Repository](10)

	for _, client := range orgGithubClient.clients {
		wg.Go(func() ([]*github.Repository, error) {
			result, _, err := client.Apps.ListRepos(context.Background(), nil)
			if err != nil {
				return nil, err
			}
			return result.Repositories, nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}

func (githubIntegration *githubIntegration) GetOrgGithubClientFromContext(ctx core.Context) (*orgGithubClient, error) {
	tenant := core.GetTenant(ctx)

	// get the installation id from the database
	appInstallations, err := githubIntegration.githubAppInstallationRepository.FindByOrganizationId(tenant.GetID())
	if err != nil {
		slog.Error("could not find github app installations", "err", err)
		return nil, err
	}

	clients := make([]*github.Client, 0)
	for _, appInstallation := range appInstallations {
		// Wrap the shared transport for use with the integration ID 1 authenticating with installation ID 99.
		// itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, 923505, 52040746, "flawfix.2024-06-20.private-key.pem")
		// Or for endpoints that require JWT authentication
		itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, githubIntegration.githubAppId, int64(appInstallation.InstallationID), "flawfix.2024-06-20.private-key.pem")

		if err != nil {
			return nil, err
		}

		// Use installation transport with client.
		client := github.NewClient(&http.Client{Transport: itr})
		clients = append(clients, client)
	}

	return &orgGithubClient{
		clients: clients,
	}, nil
}

func (githubIntegration *githubIntegration) Webhook(ctx core.Context) error {
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
		slog.Info("new app installation", "installationId", *event.Installation.ID, "senderId", *event.Sender.ID)

		githubAppInstallation := models.GithubAppInstallation{
			InstallationID:                         int(*event.Installation.ID),
			InstallationCreatedWebhookReceivedTime: time.Now(),
		}
		// save the new installation to the database
		err := githubIntegration.githubAppInstallationRepository.Save(nil, &githubAppInstallation)
		if err != nil {
			slog.Error("could not save github app installation", "err", err)
			return err
		}
		// save to payload as json to file
		return nil
	}

	return ctx.JSON(200, "ok")
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
