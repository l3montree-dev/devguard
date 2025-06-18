// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"fmt"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

type jiraRepository struct {
	*Project
	JiraIntegrationID int `json:"jiraIntegrationID"`
}

func (r *jiraRepository) toRepository() core.Repository {
	return core.Repository{
		ID:          fmt.Sprintf("jira:%d:%s", r.JiraIntegrationID, r.ID),
		Label:       r.Name,
		Description: r.Description,
	}
}

type JiraIntegration struct {
	jiraIntegrationRepository core.JiraIntegrationRepository
}

var _ core.ThirdPartyIntegration = &JiraIntegration{}

func NewJiraIntegration(db core.DB) *JiraIntegration {
	jiraIntegrationRepository := repositories.NewJiraIntegrationRepository(db)
	return &JiraIntegration{
		jiraIntegrationRepository: jiraIntegrationRepository,
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
	// Jira integration does not have repositories in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing repositories")
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
func (i *JiraIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	// Jira integration does not support creating issues in the same way as GitLab or GitHub
	return fmt.Errorf("Jira integration does not support creating issues")
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
