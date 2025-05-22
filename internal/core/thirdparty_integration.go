package core

import (
	"context"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

type Repository struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type User struct {
	Name      string  `json:"name"`
	ID        string  `json:"id"`
	AvatarURL *string `json:"avatarUrl"`

	Role string `json:"role"`
}

type IntegrationID string

const (
	GitLabIntegrationID IntegrationID = "gitlab"
	GitHubIntegrationID IntegrationID = "github"
	AggregateID         IntegrationID = "aggregate"
)

type ThirdPartyIntegration interface {
	WantsToHandleWebhook(ctx Context) bool
	HandleWebhook(ctx Context) error

	ListRepositories(ctx Context) ([]Repository, error)

	HandleEvent(event any) error
	CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error
	CloseIssue(ctx context.Context, state string, repoId string, vuln models.Vuln) error
	ReopenIssue(ctx context.Context, repoId string, vuln models.Vuln) error
	UpdateIssue(ctx context.Context, asset models.Asset, repoId string, vuln models.Vuln) error

	GetUsers(org models.Org) []User

	GetID() IntegrationID
}

type IntegrationAggregate interface {
	ThirdPartyIntegration
	GetIntegration(id IntegrationID) ThirdPartyIntegration
}
