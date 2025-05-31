package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

type Repository struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Image       string `json:"image"`
	Description string `json:"description"`

	IsDeveloper  bool `json:"isDeveloper"`
	IsMaintainer bool `json:"isMaintainer"`
	IsOwner      bool `json:"isOwner"`

	GitProvider string `json:"gitProvider"`
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
	ListOrgs(ctx Context) ([]models.Org, error)
	GetOrg(ctx context.Context, userID string, providerID string, groupID string) (models.Org, error)

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

type ExternalEntitySlug string

func (e ExternalEntitySlug) String() string {
	return string(e)
}

func (e ExternalEntitySlug) IsValid() bool {
	// needs to contain @
	return len(e) > 0 && strings.Contains(string(e), "@")
}

func (e ExternalEntitySlug) ProviderID() string {
	// everything after the @ is the provider ID
	parts := strings.SplitN(string(e), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func (e ExternalEntitySlug) EntityID() string {
	// everything before the @ is the entity ID
	parts := strings.SplitN(string(e), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func FromStringToExternalEntitySlug(s string) (ExternalEntitySlug, error) {
	if !strings.Contains(s, "@") {
		return "", fmt.Errorf("invalid external entity slug: %s", s)
	}
	return ExternalEntitySlug(s), nil
}
