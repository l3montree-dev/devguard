package githubint

import (
	"context"

	"github.com/google/go-github/v62/github"
)

// wrapper around the github package - which provides only the methods
// we need
type githubClientFacade interface {
	CreateIssue(ctx context.Context, owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	CreateIssueComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	EditIssue(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	EditIssueLabel(ctx context.Context, owner string, repo string, name string, label *github.Label) (*github.Label, *github.Response, error)
	IsCollaboratorInRepository(ctx context.Context, owner string, repoId string, userId int64, opts *github.ListCollaboratorsOptions) (bool, error)
}
