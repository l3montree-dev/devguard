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

package githubint

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

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

// groups multiple github clients - since an org can have multiple installations
func newGithubBatchClient(appInstallations []models.GithubAppInstallation) (*githubBatchClient, error) {
	if len(appInstallations) == 0 {
		slog.Error("no github app installations found")
		return nil, ErrNoGithubAppInstallation
	}

	clients := make([]githubClient, 0)
	for _, appInstallation := range appInstallations {
		client, err := NewGithubClient(appInstallation.InstallationID)
		if err != nil {
			slog.Error("error creating github client", "err", err)
			return nil, err
		}

		clients = append(clients, client)
	}

	return &githubBatchClient{
		clients: clients,
	}, nil
}

func fetchAllRepos(client githubClient) ([]*github.Repository, error) {
	result, _, err := client.Apps.ListRepos(context.Background(), &github.ListOptions{
		Page:    1,
		PerPage: 100,
	})

	if err != nil {
		return nil, err
	}

	repos := result.Repositories
	// check if there is more to fetch
	for len(repos) < *result.TotalCount {
		result, _, err = client.Apps.ListRepos(context.Background(), &github.ListOptions{
			Page:    len(repos) / 100,
			PerPage: 100,
		})
		if err != nil {
			return nil, err
		}
		repos = append(repos, result.Repositories...)
	}

	return repos, nil
}

func (githubOrgClient *githubBatchClient) ListRepositories(
	search string,
) ([]githubRepository, error) {
	wg := utils.ErrGroup[[]githubRepository](10)

	for _, client := range githubOrgClient.clients {
		wg.Go(func() ([]githubRepository, error) {

			result, err := fetchAllRepos(client)
			if err != nil {
				return nil, err
			}

			// filter the result set based on the search query
			if search != "" {
				result = utils.Filter(result, func(el *github.Repository) bool {
					return strings.Contains(*el.FullName, search)
				})
			}

			return utils.Map(result, func(el *github.Repository) githubRepository {
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

var _ githubClientFacade = &githubClient{}

func (client githubClient) CreateIssue(ctx context.Context, owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	return client.Issues.Create(ctx, owner, repo, issue)
}

func (client githubClient) CreateIssueComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
	return client.Issues.CreateComment(ctx, owner, repo, number, comment)
}

func (client githubClient) EditIssue(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	return client.Issues.Edit(ctx, owner, repo, number, issue)
}

func (client githubClient) EditIssueLabel(ctx context.Context, owner string, repo string, name string, label *github.Label) (*github.Label, *github.Response, error) {
	return client.Issues.EditLabel(ctx, owner, repo, name, label)
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

func (client githubClient) GetRepositoryCollaborators(ctx context.Context, owner string, repoId string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
	return client.Repositories.ListCollaborators(ctx, owner, repoId, opts)
}

func (client githubClient) IsCollaboratorInRepository(ctx context.Context, owner string, repoId string, userId int64, opts *github.ListCollaboratorsOptions) (bool, error) {
	collaborators, _, err := client.GetRepositoryCollaborators(ctx, owner, repoId, opts)
	if err != nil {
		return false, err
	}
	for _, user := range collaborators {
		if userId == *user.ID {
			return true, nil
		}
	}
	return false, nil
}
