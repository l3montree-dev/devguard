package shared

import (
	"context"
	"fmt"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

type IntegrationID string

const (
	GitLabIntegrationID        IntegrationID = "gitlab"
	GitHubIntegrationID        IntegrationID = "github"
	AggregateID                IntegrationID = "aggregate"
	JiraIntegrationID          IntegrationID = "jira"
	WebhookIntegrationID       IntegrationID = "webhook"
	TrivyOperatorIntegrationID IntegrationID = "trivy-operator"
)

type ThirdPartyIntegration interface {
	WantsToHandleWebhook(ctx Context) bool
	HandleWebhook(ctx Context) error
	ListOrgs(ctx Context) ([]models.Org, error)                                                                         // maps identity providers to orgs
	ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []Role, error)                 // maps groups to projects
	ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []Role, error) // maps projects to assets
	ListRepositories(ctx Context) ([]dtos.GitRepository, error)
	HasAccessToExternalEntityProvider(ctx Context, externalEntityProviderID string) (bool, error)
	HandleEvent(ctx context.Context, event any, userAgent *string) error
	CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string, userAgent *string) error
	UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, userAgent *string) error
	CreateLabels(ctx context.Context, asset models.Asset) error
	CompareIssueStatesAndResolveDifferences(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) error
	GetID() IntegrationID
}

type IntegrationAggregate interface {
	ThirdPartyIntegration
	GetIntegration(id IntegrationID) ThirdPartyIntegration
	GetUsers(org models.Org) []dtos.UserDTO
}

type ExternalEntitySlug string

func MaybeGetArtifact(ctx Context) (models.Artifact, error) {
	val := ctx.Get("artifact")
	if val == nil {
		return models.Artifact{}, fmt.Errorf("artifact not found in context")
	}
	if artifact, ok := val.(*models.Artifact); ok {
		return *artifact, nil
	}
	if artifact, ok := val.(models.Artifact); ok {
		return artifact, nil
	}
	return models.Artifact{}, fmt.Errorf("artifact context value has unexpected type %T", val)
}
