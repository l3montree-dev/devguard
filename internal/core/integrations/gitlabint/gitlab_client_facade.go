package gitlabint

import (
	"context"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type gitlabClientFacade interface {
	Whoami(ctx context.Context) (*gitlab.User, *gitlab.Response, error)

	GetClientID() string
	GetProviderID() *string

	ListProjects(ctx context.Context, opt *gitlab.ListProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error)
	ListGroups(ctx context.Context, opt *gitlab.ListGroupsOptions) ([]*gitlab.Group, *gitlab.Response, error)
	GetGroup(ctx context.Context, groupId int) (*gitlab.Group, *gitlab.Response, error)
	GetMemberInGroup(ctx context.Context, userId int, groupId int) (*gitlab.GroupMember, *gitlab.Response, error)
	GetMemberInProject(ctx context.Context, userId int, projectId int) (*gitlab.ProjectMember, *gitlab.Response, error)
	ListProjectsInGroup(ctx context.Context, groupId int, opt *gitlab.ListGroupProjectsOptions) ([]*gitlab.Project, *gitlab.Response, error)

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

	IsProjectMember(ctx context.Context, projectId int, userId int, options *gitlab.ListProjectMembersOptions) (bool, error)

	InviteReporter(ctx context.Context, projectId int, userId int) (*gitlab.ProjectMember, *gitlab.Response, error)
}
