package shared

import (
	"context"
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	dtos "github.com/l3montree-dev/devguard/dto"
)

type GitRepository struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Image       string `json:"image"`
	Description string `json:"description"`

	IsDeveloper  bool `json:"isDeveloper"`
	IsMaintainer bool `json:"isMaintainer"`
	IsOwner      bool `json:"isOwner"`

	GitProvider string `json:"gitProvider"`
}

type IntegrationID string

const (
	GitLabIntegrationID  IntegrationID = "gitlab"
	GitHubIntegrationID  IntegrationID = "github"
	AggregateID          IntegrationID = "aggregate"
	JiraIntegrationID    IntegrationID = "jira"
	WebhookIntegrationID IntegrationID = "webhook"
)

type ThirdPartyIntegration interface {
	WantsToHandleWebhook(ctx Context) bool
	HandleWebhook(ctx Context) error

	ListOrgs(ctx Context) ([]models.Org, error) // maps identity providers to orgs

	ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []Role, error)                 // maps groups to projects
	ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []Role, error) // maps projects to assets

	ListRepositories(ctx Context) ([]GitRepository, error)

	HasAccessToExternalEntityProvider(ctx Context, externalEntityProviderID string) (bool, error)

	HandleEvent(event any) error
	CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error
	UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln) error

	CreateLabels(ctx context.Context, asset models.Asset) error

	GetID() IntegrationID
}

type IntegrationAggregate interface {
	ThirdPartyIntegration
	GetIntegration(id IntegrationID) ThirdPartyIntegration
	GetUsers(org models.Org) []dtos.UserDTO
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

func (e ExternalEntitySlug) Slug() string {
	// everything before the @ is the entity ID
	parts := strings.SplitN(string(e), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func (e ExternalEntitySlug) SameAs(slug string) bool {
	// convert
	otherSlug, err := FromStringToExternalEntitySlug(slug)
	if err != nil {
		return false
	}
	return e.Slug() == otherSlug.Slug() && e.ProviderID() == otherSlug.ProviderID()
}

func FromStringToExternalEntitySlug(s string) (ExternalEntitySlug, error) {
	if !strings.Contains(s, "@") {
		return "", fmt.Errorf("invalid external entity slug: %s", s)
	}
	return ExternalEntitySlug(s), nil
}
