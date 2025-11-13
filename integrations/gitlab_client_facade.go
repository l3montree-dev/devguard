package integrations

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type GitlabClientFactory interface {
	FromIntegration(integration models.GitLabIntegration) (GitlabClientFacade, error)
	FromIntegrationUUID(id uuid.UUID) (GitlabClientFacade, error)
	FromOauth2Token(token models.GitLabOauth2Token, enableClientCache bool) (GitlabClientFacade, error)
	FromAccessToken(accessToken string, baseURL string) (GitlabClientFacade, error)
}

type GitlabClientFacade interface {
	Whoami(ctx context.Context) (*gitlab.User, *gitlab.Response, error)

	GetVersion(ctx context.Context) (*gitlab.Version, *gitlab.Response, error)
	FetchGroupAvatarBase64(groupID int) (string, error)
	FetchProjectAvatarBase64(projectID int) (string, error)

	GetClientID() string

	ListProjects(ctx context.Context, opt *gitlab.ListProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error)
	ListGroups(ctx context.Context, opt *gitlab.ListGroupsOptions) ([]*gitlab.Group, *gitlab.Response, error)
	GetGroup(ctx context.Context, groupID int) (*gitlab.Group, *gitlab.Response, error)
	GetMemberInGroup(ctx context.Context, userID int, groupID int) (*gitlab.GroupMember, *gitlab.Response, error)
	GetMemberInProject(ctx context.Context, userID int, projectID int) (*gitlab.ProjectMember, *gitlab.Response, error)
	ListProjectsInGroup(ctx context.Context, groupID int, opt *gitlab.ListGroupProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error)
	GetProjectIssues(projectID int, opt *gitlab.ListProjectIssuesOptions) ([]*gitlab.Issue, *gitlab.Response, error)

	CreateIssue(ctx context.Context, pid int, opt *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	CreateIssueComment(ctx context.Context, pid int, issue int, opt *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error)
	EditIssue(ctx context.Context, pid int, issue int, opt *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	EditIssueLabel(ctx context.Context, pid int, issue int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error)
	CreateNewLabel(ctx context.Context, projectID int, label *gitlab.CreateLabelOptions) (*gitlab.Label, *gitlab.Response, error)
	ListLabels(ctx context.Context, projectID int, opt *gitlab.ListLabelsOptions) ([]*gitlab.Label, *gitlab.Response, error)
	UpdateLabel(ctx context.Context, projectID int, labelID int, opt *gitlab.UpdateLabelOptions) (*gitlab.Label, *gitlab.Response, error)

	ListProjectHooks(ctx context.Context, projectID int, options *gitlab.ListProjectHooksOptions) ([]*gitlab.ProjectHook, *gitlab.Response, error)
	AddProjectHook(ctx context.Context, projectID int, opt *gitlab.AddProjectHookOptions) (*gitlab.ProjectHook, *gitlab.Response, error)
	DeleteProjectHook(ctx context.Context, projectID int, hookID int) (*gitlab.Response, error)

	ListVariables(ctx context.Context, projectID int, options *gitlab.ListProjectVariablesOptions) ([]*gitlab.ProjectVariable, *gitlab.Response, error)
	CreateVariable(ctx context.Context, projectID int, opt *gitlab.CreateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error)
	UpdateVariable(ctx context.Context, projectID int, key string, opt *gitlab.UpdateProjectVariableOptions) (*gitlab.ProjectVariable, *gitlab.Response, error)
	RemoveVariable(ctx context.Context, projectID int, key string) (*gitlab.Response, error)

	CreateMergeRequest(ctx context.Context, project string, opt *gitlab.CreateMergeRequestOptions) (*gitlab.MergeRequest, *gitlab.Response, error)
	GetProject(ctx context.Context, projectID int) (*gitlab.Project, *gitlab.Response, error)

	IsProjectMember(ctx context.Context, projectID int, userID int, options *gitlab.ListProjectMembersOptions) (bool, error)

	InviteReporter(ctx context.Context, projectID int, userID int) (*gitlab.ProjectMember, *gitlab.Response, error)
}
