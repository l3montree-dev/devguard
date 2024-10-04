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
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/xanzy/go-gitlab"
)

type gitlabClient struct {
	models.GitLabIntegration
	*gitlab.Client
}
type gitlabBatchClient struct {
	clients []gitlabClient
}

var NoGitlabIntegrationError = fmt.Errorf("no gitlab app installations found")

// groups multiple gitlab clients - since an org can have multiple installations
func newGitLabBatchClient(gitlabIntegrations []models.GitLabIntegration) (*gitlabBatchClient, error) {
	if len(gitlabIntegrations) == 0 {
		slog.Error("no gitlab app installations found")
		return nil, NoGitlabIntegrationError
	}

	clients := make([]gitlabClient, 0)
	for _, integration := range gitlabIntegrations {
		client, _ := NewGitlabClient(integration)
		clients = append(clients, client)
	}

	return &gitlabBatchClient{
		clients: clients,
	}, nil
}

func (gitlabOrgClient *gitlabBatchClient) ListRepositories(search string) ([]gitlabRepository, error) {
	wg := utils.ErrGroup[[]gitlabRepository](10)
	options := &gitlab.ListProjectsOptions{
		MinAccessLevel: gitlab.Ptr(gitlab.ReporterPermissions),
	}

	if search != "" {
		options.Search = gitlab.Ptr(search)
	}

	for _, client := range gitlabOrgClient.clients {
		wg.Go(func() ([]gitlabRepository, error) {
			result, _, err := client.Projects.ListProjects(options)
			if err != nil {
				return nil, err
			}

			return utils.Map(result, func(el *gitlab.Project) gitlabRepository {
				return gitlabRepository{Project: el, gitlabIntegrationId: client.GitLabIntegration.ID.String()}
			}), nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}

func (client gitlabClient) CreateIssue(ctx context.Context, projectId int, issue *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.CreateIssue(projectId, issue)
}

func (client gitlabClient) CreateIssueComment(ctx context.Context, projectId int, issueId int, comment *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error) {
	return client.Notes.CreateIssueNote(projectId, issueId, comment)
}

func (client gitlabClient) EditIssue(ctx context.Context, projectId int, issueId int, issue *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.UpdateIssue(projectId, issueId, issue)
}

func (client gitlabClient) EditIssueLabel(ctx context.Context, projectId int, issueId int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error) {
	// fetch the issue to check the existing labels
	issue, _, err := client.Issues.GetIssue(projectId, issueId)
	if err != nil {
		return nil, err
	}

	// remove all devguard labels
	issueLabels := make([]string, 0)
	for _, l := range issue.Labels {
		if strings.HasPrefix(l, "devguard:") {
			continue
		}
		issueLabels = append(issueLabels, l)
	}

	// now add the new label
	issueLabels = append(issueLabels, utils.Map(labels, func(l *gitlab.CreateLabelOptions) string {
		return *l.Name
	})...)

	createdLabels := make([]*gitlab.Label, 0)
	// make sure each label exists
	for _, label := range labels {
		// make sure to create the label beforehand
		l, _, err := client.Labels.CreateLabel(projectId, label)
		if err != nil {
			return nil, err
		}
		createdLabels = append(createdLabels, l)
	}

	_, _, err = client.Issues.UpdateIssue(projectId, issueId, &gitlab.UpdateIssueOptions{
		Labels: gitlab.Ptr(gitlab.LabelOptions(issueLabels)),
	})

	return nil, err
}

func NewGitlabClient(integration models.GitLabIntegration) (gitlabClient, error) {

	// Use installation transport with client.
	client, err := gitlab.NewClient(integration.AccessToken, gitlab.WithBaseURL(integration.GitLabUrl))
	if err != nil {
		return gitlabClient{}, err
	}

	return gitlabClient{
		Client:            client,
		GitLabIntegration: integration,
	}, nil
}
