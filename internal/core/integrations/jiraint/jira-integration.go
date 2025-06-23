// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type jiraRepository struct {
	*Project
	JiraIntegrationID string `json:"jiraIntegrationID"`
}

func (r *jiraRepository) toRepository() core.Repository {
	return core.Repository{
		ID:          fmt.Sprintf("jira:%s:%s", r.JiraIntegrationID, r.ID),
		Label:       r.Name,
		Description: r.Description,
	}
}

type JiraIntegration struct {
	jiraIntegrationRepository core.JiraIntegrationRepository
	aggregatedVulnRepository  core.VulnRepository
}

var _ core.ThirdPartyIntegration = &JiraIntegration{}

func NewJiraIntegration(db core.DB) *JiraIntegration {
	jiraIntegrationRepository := repositories.NewJiraIntegrationRepository(db)
	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)
	return &JiraIntegration{
		jiraIntegrationRepository: jiraIntegrationRepository,
		aggregatedVulnRepository:  aggregatedVulnRepository,
	}
}

func (i *JiraIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	// Jira integration does not handle webhooks directly
	return false
}
func (i *JiraIntegration) HandleWebhook(ctx core.Context) error {
	// Jira integration does not handle webhooks directly
	return nil
}
func (i *JiraIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// Jira integration does not have organizations in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing organizations")
}
func (i *JiraIntegration) ListGroups(ctx core.Context, userID string, providerID string) ([]models.Project, error) {
	// Jira integration does not have groups in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing groups")
}
func (i *JiraIntegration) ListProjects(ctx core.Context, userID string, providerID string, groupID string) ([]models.Asset, error) {
	// Jira integration does not have projects in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing projects")
}
func (i *JiraIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {

	fmt.Println("es wurde aufgerufen!!!!")

	if !core.HasOrganization(ctx) {
		return nil, fmt.Errorf("organization is required to list repositories")
	}

	org := core.GetOrg(ctx)

	repos := []core.Repository{}

	if org.JiraIntegrations != nil {
		jiraClient, err := NewJiraBatchClient(org.JiraIntegrations)
		if err != nil {
			return nil, fmt.Errorf("failed to create Jira client: %w", err)
		}

		// get the repos
		r, err := jiraClient.ListRepositories(ctx.QueryParam("search"))
		if err != nil {
			return nil, fmt.Errorf("failed to get repositories from Jira: %w", err)
		}

		repos = append(repos, utils.Map(r, func(repo jiraRepository) core.Repository {
			return repo.toRepository()
		})...)
		return repos, nil
	}
	return nil, fmt.Errorf("no Jira integration found for organization %s", org.GetID())

}
func (i *JiraIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	// Jira integration does not have access control in the same way as GitLab or GitHub
	return false, fmt.Errorf("Jira integration does not support access control for external entity providers")
}
func (i *JiraIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// Jira integration does not have groups in the same way as GitLab or GitHub
	return "", fmt.Errorf("Jira integration does not support getting role in group")
}
func (i *JiraIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// Jira integration does not have projects in the same way as GitLab or GitHub
	return "", fmt.Errorf("Jira integration does not support getting role in project")
}
func (i *JiraIntegration) HandleEvent(event any) error {
	// Jira integration does not handle events in the same way as GitLab or GitHub
	return fmt.Errorf("Jira integration does not support handling events")
}

func extractIntegrationIdFromRepoId(repoId string) (uuid.UUID, error) {
	return uuid.Parse(strings.Split(repoId, ":")[1])
}

func extractProjectIdFromRepoId(repoId string) (int, error) {
	return strconv.Atoi(strings.Split(repoId, ":")[2])
}

func fromJiraIntegrationToClient(integration models.JiraIntegration) (*JiraClient, error) {
	if integration.ID == uuid.Nil || integration.AccessToken == "" || integration.URL == "" || integration.UserEmail == "" {
		return nil, fmt.Errorf("invalid Jira integration: %v", integration)
	}

	return &JiraClient{
		JiraIntegrationID: integration.ID.String(),
		AccessToken:       integration.AccessToken,
		BaseURL:           integration.URL,
		UserEmail:         integration.UserEmail,
	}, nil
}

func (i *JiraIntegration) getClientBasedOnAsset(asset models.Asset) (*JiraClient, int, error) {
	if asset.RepositoryID == nil || !strings.HasPrefix(*asset.RepositoryID, "jira:") {
		return nil, 0, fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
	}

	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(integrationUUID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Jira client for integration %s: %w", integrationUUID, err)
	}

	projectId, err := extractProjectIdFromRepoId(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract project id from repo id: %w", err)
	}

	client, err := fromJiraIntegrationToClient(jiraIntegration)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create Jira client from integration %s: %w", integrationUUID, err)
	}

	return client, projectId, nil
}

func (i *JiraIntegration) createDependencyVulnIssue(ctx context.Context, vuln *models.DependencyVuln, asset models.Asset, client *JiraClient, assetVersionName string, justification string, orgSlug string, projectSlug string, projectId int) (*Issue, error) {
	// Implementation for creating a dependency vulnerability issue in Jira
	// This is a placeholder and should be replaced with actual implementation
	return nil, fmt.Errorf("createDependencyVulnIssue not implemented")
}

func (i *JiraIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client *JiraClient, assetVersionName string, justification string, orgSlug string, projectSlug string, projectId int) (*Issue, error) {
	// Implementation for creating a first-party vulnerability issue in Jira
	return nil, fmt.Errorf("createFirstPartyVulnIssue not implemented")
}

func (i *JiraIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "jira:") {
		return fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	client, projectId, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
	}
	var createdIssue *Issue

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = i.createDependencyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = i.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	}

	vuln.SetTicketID(fmt.Sprintf("jira:%s:%d", projectId, createdIssue.ID))
	vuln.SetTicketURL(fmt.Sprintf("%s/browse/%s", client.BaseURL, createdIssue.Key))
	vuln.SetManualTicketCreation(userID != "system")

	vulnEvent := models.NewMitigateEvent(
		vuln.GetID(),
		vuln.GetType(),
		userID,
		justification,
		map[string]any{
			"ticketId": vuln.GetTicketID(),
			//TODO: set the ticket URL
			//	"ticketUrl": createdIssue.WebURL,
		})

	err = i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
	if err != nil {
		//TODO: if error did happen, we should remove the issue from Jira
		return fmt.Errorf("failed to save vulnerability with ticket information: %w", err)
	}

	return nil
}
func (i *JiraIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	// Jira integration does not support updating issues in the same way as GitLab or GitHub
	return fmt.Errorf("Jira integration does not support updating issues")
}
func (i *JiraIntegration) GetUsers(org models.Org) []core.User {
	// Jira integration does not have users in the same way as GitLab or GitHub
	return nil
}
func (i *JiraIntegration) GetID() core.IntegrationID {
	return core.JiraIntegrationID
}

func (i *JiraIntegration) TestAndSave(ctx core.Context) error {
	var data struct {
		Url       string `json:"url"`
		Token     string `json:"token"`
		Name      string `json:"name"`
		UserEmail string `json:"userEmail"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.Url == "" || data.Token == "" || data.UserEmail == "" {
		return ctx.JSON(400, "url, token and userEmail are required")
	}

	//todo: check if the token valid and get the min access level
	// For now, we assume the token is valid and has sufficient access

	jiraIntegration := &models.JiraIntegration{
		URL:         data.Url,
		AccessToken: data.Token,
		Name:        data.Name,
		UserEmail:   data.UserEmail,
		OrgID:       (core.GetOrg(ctx).GetID()),
	}

	if err := i.jiraIntegrationRepository.Save(nil, jiraIntegration); err != nil {
		return err
	}
	return ctx.JSON(200, common.JiraIntegrationDTO{
		ID:              jiraIntegration.ID.String(),
		Name:            jiraIntegration.Name,
		URL:             jiraIntegration.URL,
		UserEmail:       jiraIntegration.UserEmail,
		ObfuscatedToken: jiraIntegration.AccessToken[:4] + "************" + jiraIntegration.AccessToken[len(jiraIntegration.AccessToken)-4:],
	})
}
