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

package gitlabint

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type gitlabClient struct {
	*gitlab.Client
	// the id of the client - we need to use this client to connect to any gitlab projects again.
	// might be a gitlab_integration id or a gitlab oauth2 token id.
	clientID      string
	gitProviderID *string
}

type gitlabBatchClient struct {
	clients []shared.GitlabClientFacade
}

var ErrNoGitlabIntegration = fmt.Errorf("no gitlab app installations found")

// groups multiple gitlab clients - since an org can have multiple installations
func NewGitlabBatchClient(clients []shared.GitlabClientFacade) *gitlabBatchClient {
	return &gitlabBatchClient{
		clients: clients,
	}
}

func groupToProject(avatarBase64 *string, group *gitlab.Group, providerID string) models.Project {
	var externalEntityParentID *string = nil
	if group.ParentID > 0 {
		externalEntityParentID = utils.Ptr(fmt.Sprintf("%d", group.ParentID))
	}

	return models.Project{
		Name:                     group.FullName,
		Description:              group.Description,
		Avatar:                   avatarBase64,
		Slug:                     slug.Make(group.Path),
		ExternalEntityProviderID: &providerID,
		ExternalEntityParentID:   externalEntityParentID,
		ExternalEntityID:         utils.Ptr(fmt.Sprintf("%d", group.ID)),
	}
}

func projectToAsset(avatarBase64 *string, project *gitlab.Project, providerID string) models.Asset {
	return models.Asset{
		Name:                     project.Name,
		Avatar:                   avatarBase64,
		Description:              project.Description,
		Slug:                     slug.Make(project.Path),
		ExternalEntityProviderID: &providerID,
		ExternalEntityID:         utils.Ptr(fmt.Sprintf("%d", project.ID)),
	}
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
				return gitlabRepository{Project: el, gitlabIntegrationID: client.GetClientID()}
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

func (client gitlabClient) GetGroup(ctx context.Context, groupID int) (*gitlab.Group, *gitlab.Response, error) {
	return client.Groups.GetGroup(groupID, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetProjectIssues(projectID int, opt *gitlab.ListProjectIssuesOptions) ([]*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.ListProjectIssues(projectID, opt, nil)
}

func (client gitlabClient) CreateNewLabel(ctx context.Context, projectID int, label *gitlab.CreateLabelOptions) (*gitlab.Label, *gitlab.Response, error) {
	return client.Labels.CreateLabel(projectID, label, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetMemberInGroup(ctx context.Context, userID int, groupID int) (*gitlab.GroupMember, *gitlab.Response, error) {
	return client.GroupMembers.GetInheritedGroupMember(groupID, userID, gitlab.WithContext(ctx))
}

func (client gitlabClient) Whoami(ctx context.Context) (*gitlab.User, *gitlab.Response, error) {
	return client.Users.CurrentUser(gitlab.WithContext(ctx))
}

func (client gitlabClient) GetVersion(ctx context.Context) (*gitlab.Version, *gitlab.Response, error) {
	return client.Version.GetVersion()
}

func (client gitlabClient) FetchProjectAvatarBase64(projectID int) (string, error) {
	b, _, err := client.Projects.DownloadAvatar(projectID, nil)

	if err != nil {
		return "", fmt.Errorf("failed to download avatar: %w", err)
	}

	bytes, err := io.ReadAll(b)
	if err != nil {
		return "", fmt.Errorf("failed to read avatar bytes: %w", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(bytes)
	if base64Encoded == "" {
		return "", fmt.Errorf("failed to encode avatar to base64")
	}

	return base64Encoded, nil
}

func (client gitlabClient) FetchGroupAvatarBase64(groupID int) (string, error) {
	b, _, err := client.Groups.DownloadAvatar(groupID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to download avatar: %w", err)
	}

	bytes, err := io.ReadAll(b)
	if err != nil {
		return "", fmt.Errorf("failed to read avatar bytes: %w", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(bytes)
	if base64Encoded == "" {
		return "", fmt.Errorf("failed to encode avatar to base64")
	}

	return base64Encoded, nil
}

func (client gitlabClient) GetMemberInProject(ctx context.Context, userID int, projectID int) (*gitlab.ProjectMember, *gitlab.Response, error) {
	return client.ProjectMembers.GetInheritedProjectMember(projectID, userID, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListProjectsInGroup(ctx context.Context, groupID int, opt *gitlab.ListGroupProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error) {
	return client.Groups.ListGroupProjects(groupID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) UpdateVariable(ctx context.Context, projectID int, key string, opt *gitlab.UpdateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.UpdateVariable(projectID, key, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) RemoveVariable(ctx context.Context, projectID int, key string) (*gitlab.Response, error) {
	return client.ProjectVariables.RemoveVariable(projectID, key, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) InviteReporter(ctx context.Context, projectID int, userID int) (*gitlab.ProjectMember, *gitlab.Response, error) {
	opt := &gitlab.AddProjectMemberOptions{
		UserID:      gitlab.Ptr(userID),
		AccessLevel: gitlab.Ptr(gitlab.ReporterPermissions),
	}
	return client.ProjectMembers.AddProjectMember(projectID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) AddProjectHook(ctx context.Context, projectID int, opt *gitlab.AddProjectHookOptions) (*gitlab.ProjectHook, *gitlab.Response, error) {
	return client.Projects.AddProjectHook(projectID, opt, gitlab.WithContext(ctx))
}
func (client gitlabClient) DeleteProjectHook(ctx context.Context, projectID int, hookID int) (*gitlab.Response, error) {
	return client.Projects.DeleteProjectHook(projectID, hookID, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateMergeRequest(ctx context.Context, project string, opt *gitlab.CreateMergeRequestOptions) (*gitlab.MergeRequest, *gitlab.Response, error) {
	return client.MergeRequests.CreateMergeRequest(project, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetProject(ctx context.Context, projectID int) (*gitlab.Project, *gitlab.Response, error) {
	return client.Projects.GetProject(projectID, nil, gitlab.WithContext(ctx))
}

func (client gitlabClient) GetClientID() string {
	return client.clientID
}

func (client gitlabClient) ListProjects(ctx context.Context, opt *gitlab.ListProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error) {
	return client.Projects.ListProjects(opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListProjectMembers(ctx context.Context, projectID int, memberOptions *gitlab.ListProjectMembersOptions, requestOptions ...gitlab.RequestOptionFunc) ([]*gitlab.ProjectMember, *gitlab.Response, error) {
	return client.ProjectMembers.ListAllProjectMembers(projectID, memberOptions, requestOptions...)
}

func (client gitlabClient) IsProjectMember(ctx context.Context, projectID int, userID int, options *gitlab.ListProjectMembersOptions) (bool, error) {
	members, err := FetchPaginatedData(func(page int) ([]*gitlab.ProjectMember, *gitlab.Response, error) {
		// get the groups for this user
		return client.ListProjectMembers(ctx, projectID, &gitlab.ListProjectMembersOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: 100},
		}, nil)
	})

	if err != nil {
		return false, err
	}
	for _, member := range members {
		if member.ID == userID {
			return true, nil
		}
	}
	return false, nil

}

func (client gitlabClient) ListProjectHooks(ctx context.Context, projectID int, opt *gitlab.ListProjectHooksOptions) ([]*gitlab.ProjectHook, *gitlab.Response, error) {
	return client.Projects.ListProjectHooks(projectID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListVariables(ctx context.Context, projectID int, opt *gitlab.ListProjectVariablesOptions) ([]*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.ListVariables(projectID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListGroups(ctx context.Context, opt *gitlab.ListGroupsOptions) ([]*gitlab.Group, *gitlab.Response, error) {
	return client.Groups.ListGroups(opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateVariable(ctx context.Context, projectID int, opt *gitlab.CreateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error) {
	return client.ProjectVariables.CreateVariable(projectID, opt, gitlab.WithContext(ctx))
}
func (client gitlabClient) CreateIssue(ctx context.Context, projectID int, issue *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.CreateIssue(projectID, issue, gitlab.WithContext(ctx))
}

func (client gitlabClient) CreateIssueComment(ctx context.Context, projectID int, issueID int, comment *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error) {
	return client.Notes.CreateIssueNote(projectID, issueID, comment, gitlab.WithContext(ctx))
}

func (client gitlabClient) EditIssue(ctx context.Context, projectID int, issueID int, issueOptions *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error) {
	return client.Issues.UpdateIssue(projectID, issueID, issueOptions, gitlab.WithContext(ctx))
}

func (client gitlabClient) ListLabels(ctx context.Context, projectID int, opt *gitlab.ListLabelsOptions) ([]*gitlab.Label, *gitlab.Response, error) {
	return client.Labels.ListLabels(projectID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) UpdateLabel(ctx context.Context, projectID int, labelID int, opt *gitlab.UpdateLabelOptions) (*gitlab.Label, *gitlab.Response, error) {
	return client.Labels.UpdateLabel(projectID, labelID, opt, gitlab.WithContext(ctx))
}

func (client gitlabClient) EditIssueLabel(ctx context.Context, projectID int, issueID int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error) {
	// fetch the issue to check the existing labels
	issue, _, err := client.Issues.GetIssue(projectID, issueID, gitlab.WithContext(ctx))
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
		_, _, err := client.Labels.CreateLabel(projectID, label)
		if err != nil {
			return nil, err
		}
	}

	_, _, err = client.Issues.UpdateIssue(projectID, issueID, &gitlab.UpdateIssueOptions{
		Labels: gitlab.Ptr(gitlab.LabelOptions(issueLabels)),
	})

	return nil, err
}
