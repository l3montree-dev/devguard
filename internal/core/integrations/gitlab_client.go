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
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type gitlabClient struct {
	*gitlab.Client
	// the id of the client - we need to use this client to connect to any gitlab projects again.
	// might be a gitlab_integration id or a gitlab oauth2 token id.
	clientID      string
	gitProviderID *string
}

type gitlabClientFacade interface {
	GetClientID() string
	GetProviderID() *string

	ListProjects(ctx context.Context, opt *gitlab.ListProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error)
	ListGroups(ctx context.Context, opt *gitlab.ListGroupsOptions) ([]*gitlab.Group, *gitlab.Response, error)
	GetGroup(ctx context.Context, groupId int) (*gitlab.Group, *gitlab.Response, error)

	CreateIssue(ctx context.Context, pid int, opt *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	CreateIssueComment(ctx context.Context, pid int, issue int, opt *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error)
	EditIssue(ctx context.Context, pid int, issue int, opt *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	EditIssueLabel(ctx context.Context, pid int, issue int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error)

	ListProjectHooks(ctx context.Context, projectId int, options *gitlab.ListProjectHooksOptions) ([]*gitlab.ProjectHook, *gitlab.Response, error)
	AddProjectHook(ctx context.Context, projectId int, opt *gitlab.AddProjectHookOptions) (*gitlab.ProjectHook, *gitlab.Response, error)
	DeleteProjectHook(ctx context.Context, projectId int, hookId int) (*gitlab.Response, error)

	ListVariables(ctx context.Context, projectId int, options *gitlab.ListProjectVariablesOptions) ([]*gitlab.ProjectVariable, *gitlab.Response, error)
	CreateVariable(ctx context.Context, projectId int, opt *gitlab.CreateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error)
	UpdateVariable(ctx context.Context, projectId int, key string, opt *gitlab.UpdateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error)
	RemoveVariable(ctx context.Context, projectId int, key string) (*gitlab.Response, error)

	CreateMergeRequest(ctx context.Context, project string, opt *gitlab.CreateMergeRequestOptions) (*gitlab.MergeRequest, *gitlab.Response, error)
	GetProject(ctx context.Context, projectId int) (*gitlab.Project, *gitlab.Response, error)
}

type gitlabBatchClient struct {
	clients []gitlabClientFacade
}

var NoGitlabIntegrationError = fmt.Errorf("no gitlab app installations found")

// groups multiple gitlab clients - since an org can have multiple installations
func newGitLabBatchClient(gitlabIntegrations []models.GitLabIntegration, oauth2Config map[string]*GitlabOauth2Config, oauth2Tokens []models.GitLabOauth2Token) (*gitlabBatchClient, error) {
	clients := make([]gitlabClientFacade, 0)
	for _, integration := range gitlabIntegrations {
		client, _ := NewGitlabClient(integration)
		clients = append(clients, client)
	}

	// create oauth2 clients
	for _, token := range oauth2Tokens {
		// check if there is a matching oauth2 config
		for _, oauth2 := range oauth2Config {
			if oauth2.ProviderID == token.ProviderID {
				// great we can use the config to generate a token
				client, err := buildOauth2GitlabClient(token, oauth2)
				if err != nil {
					slog.Error("error while creating oauth2 client", "err", err)
					continue
				}

				clients = append(clients, client)
				break
			}
		}
	}

	return &gitlabBatchClient{
		clients: clients,
	}, nil
}

func groupToOrg(group *gitlab.Group, providerID string) models.Org {
	return models.Org{
		Name:          group.Name,
		Description:   group.Description,
		Slug:          fmt.Sprintf("%d@%s", group.ID, providerID),
		GitProviderID: utils.Ptr(providerID),
	}
}

func (gitlabBatchClient *gitlabBatchClient) ListGroups() ([]models.Org, error) {
	wg := utils.ErrGroup[[]models.Org](10)
	for _, client := range gitlabBatchClient.clients {
		wg.Go(func() ([]models.Org, error) {
			if client.GetProviderID() == nil {
				// just skip - we wont find any orgs for this client if the provider ID is nil
				// this can only happen for "non oa"
				return nil, nil
			}
			orgs, _, err := client.ListGroups(context.TODO(), &gitlab.ListGroupsOptions{
				MinAccessLevel: gitlab.Ptr(gitlab.ReporterPermissions),
			})
			if err != nil {
				return nil, err
			}

			return utils.Map(orgs, func(el *gitlab.Group) models.Org {
				return groupToOrg(el, *client.GetProviderID())
			}), nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}

func (gitlabOrgClient *gitlabBatchClient) ListRepositories(search string) ([]gitlabRepository, error) {
	wg := utils.ErrGroup[[]gitlabRepository](10)
	options := &gitlab.ListProjectsOptions{
		MinAccessLevel: gitlab.Ptr(gitlab.ReporterPermissions),
		Membership:     gitlab.Ptr(true),
	}

	if search != "" {
		options.Search = gitlab.Ptr(search)
	}

	for _, client := range gitlabOrgClient.clients {
		wg.Go(func() ([]gitlabRepository, error) {
			result, _, err := client.ListProjects(context.TODO(), options)
			if err != nil {
				return nil, err
			}

			return utils.Map(result, func(el *gitlab.Project) gitlabRepository {
				return gitlabRepository{Project: el, gitlabIntegrationId: client.GetClientID()}
			}), nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}

func (client gitlabClient) GetProviderID() *string {
	return client.gitProviderID
}

func (client gitlabClient) GetGroup(ctx context.Context, groupId int) (*gitlab.Group, *gitlab.Response, error) {
	return client.Groups.GetGroup(groupId, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) UpdateVariable(ctx context.Context, projectId int, key string, opt *gitlab.UpdateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.UpdateVariable(projectId, key, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) RemoveVariable(ctx context.Context, projectId int, key string) (*gitlab.Response, error) {
	return client.ProjectVariables.RemoveVariable(projectId, key, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) AddProjectHook(ctx context.Context, projectId int, opt *gitlab.AddProjectHookOptions) (*gitlab.ProjectHook, *gitlab.Response, error) {
	return client.Projects.AddProjectHook(projectId, opt, gitlab.WithContext(ctx))
}
func (client gitlabClient) DeleteProjectHook(ctx context.Context, projectId int, hookId int) (*gitlab.Response, error) {
	return client.Projects.DeleteProjectHook(projectId, hookId, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateMergeRequest(ctx context.Context, project string, opt *gitlab.CreateMergeRequestOptions) (*gitlab.MergeRequest, *gitlab.Response, error) {
	return client.MergeRequests.CreateMergeRequest(project, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetProject(ctx context.Context, projectId int) (*gitlab.Project, *gitlab.Response, error) {
	return client.Projects.GetProject(projectId, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetClientID() string {
	return client.clientID
}

func (client gitlabClient) ListProjects(ctx context.Context, opt *gitlab.ListProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error) {
	return client.Projects.ListProjects(opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListProjectHooks(ctx context.Context, projectId int, opt *gitlab.ListProjectHooksOptions) ([]*gitlab.ProjectHook, *gitlab.Response, error) {
	return client.Projects.ListProjectHooks(projectId, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListVariables(ctx context.Context, projectId int, opt *gitlab.ListProjectVariablesOptions) ([]*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.ListVariables(projectId, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListGroups(ctx context.Context, opt *gitlab.ListGroupsOptions) ([]*gitlab.Group, *gitlab.Response, error) {
	return client.Groups.ListGroups(opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateVariable(ctx context.Context, projectId int, opt *gitlab.CreateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.CreateVariable(projectId, opt, gitlab.WithContext(ctx))
}
func (client gitlabClient) CreateIssue(ctx context.Context, projectId int, issue *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.CreateIssue(projectId, issue, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateIssueComment(ctx context.Context, projectId int, issueId int, comment *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error) {
	return client.Notes.CreateIssueNote(projectId, issueId, comment, gitlab.WithContext(ctx))
}

func (client gitlabClient) EditIssue(ctx context.Context, projectId int, issueId int, issue *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.UpdateIssue(projectId, issueId, issue, gitlab.WithContext(ctx))
}

func (client gitlabClient) EditIssueLabel(ctx context.Context, projectId int, issueId int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error) {
	// fetch the issue to check the existing labels
	issue, _, err := client.Issues.GetIssue(projectId, issueId, gitlab.WithContext(ctx))
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

	// make sure each label exists
	for _, label := range labels {
		// make sure to create the label beforehand
		_, _, err := client.Labels.CreateLabel(projectId, label)
		if err != nil {
			return nil, err
		}
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
		Client:   client,
		clientID: integration.ID.String(),
	}, nil
}
