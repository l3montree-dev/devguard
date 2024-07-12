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
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type githubClient struct {
	*github.Client
	githubAppInstallationID int
}
type githubBatchClient struct {
	clients []githubClient
}

// groups multiple github client - since an org can have multiple installations
func newGithubBatchClient(appInstallations []models.GithubAppInstallation) (*githubBatchClient, error) {

	if len(appInstallations) == 0 {
		slog.Error("no github app installations found")
		return nil, NoGithubAppInstallationError
	}

	clients := make([]githubClient, 0)
	for _, appInstallation := range appInstallations {
		client, _ := NewGithubClient(appInstallation.InstallationID)

		clients = append(clients, client)
	}

	return &githubBatchClient{
		clients: clients,
	}, nil
}

func (githubOrgClient *githubBatchClient) ListRepositories() ([]githubRepository, error) {
	wg := utils.ErrGroup[[]githubRepository](10)

	for _, client := range githubOrgClient.clients {
		wg.Go(func() ([]githubRepository, error) {
			result, _, err := client.Apps.ListRepos(context.Background(), nil)
			if err != nil {
				return nil, err
			}
			return utils.Map(result.Repositories, func(el *github.Repository) githubRepository {
				return githubRepository{el, client.githubAppInstallationID}
			}), nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}

func NewGithubClient(installationID int) (githubClient, error) {
	appId := os.Getenv("GITHUB_APP_ID")
	if appId == "" {
		panic("GITHUB_APP_ID is not set")
	}
	appIdInt, err := strconv.Atoi(appId)
	if err != nil {
		return githubClient{}, err
	}

	// Wrap the shared transport for use with the integration ID 1 authenticating with installation ID 99.
	// itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, 923505, 52040746, "devguard.2024-06-20.private-key.pem")
	// Or for endpoints that require JWT authentication
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, int64(appIdInt), int64(installationID), os.Getenv("GITHUB_PRIVATE_KEY"))

	if err != nil {
		return githubClient{}, err
	}

	// Use installation transport with client.
	client := github.NewClient(&http.Client{Transport: itr})

	return githubClient{
		Client:                  client,
		githubAppInstallationID: installationID,
	}, nil
}
