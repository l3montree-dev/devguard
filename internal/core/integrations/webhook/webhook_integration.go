// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package webhook

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

type WebhookIntegration struct {
	webhookRepository core.WebhookIntegrationRepository
}

var _ core.ThirdPartyIntegration = &WebhookIntegration{}

func NewWebhookIntegration(db core.DB) *WebhookIntegration {
	webhookRepository := repositories.NewWebhookRepository(db)
	return &WebhookIntegration{
		webhookRepository: webhookRepository,
	}
}

func (w *WebhookIntegration) Delete(ctx core.Context) error {
	id := ctx.Param("id")
	if id == "" {
		return ctx.JSON(400, "id is required")
	}

	uuidID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, "invalid id format")
	}

	if err := w.webhookRepository.Delete(nil, uuidID); err != nil {
		slog.Error("failed to delete webhook integration", "err", err)
		return ctx.JSON(500, "failed to delete webhook integration")
	}
	return ctx.JSON(200, "Webhook integration deleted successfully")
}

func (w *WebhookIntegration) Update(ctx core.Context) error {
	var data struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		SbomEnabled bool   `json:"sbomEnabled"`
		VulnEnabled bool   `json:"vulnEnabled"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.URL == "" {
		return ctx.JSON(400, "url is required")
	}

	uuidID, err := uuid.Parse(data.ID)
	if err != nil {
		return ctx.JSON(400, "invalid id format")
	}
	webhookIntegration := &models.WebhookIntegration{

		Model: models.Model{
			ID: uuidID,
		},
		Name:        &data.Name,
		Description: &data.Description,
		URL:         data.URL,
		Secret:      &data.Secret,
		SbomEnabled: data.SbomEnabled,
		VulnEnabled: data.VulnEnabled,
		OrgID:       core.GetOrg(ctx).GetID(),
	}

	if err := w.webhookRepository.Save(nil, webhookIntegration); err != nil {
		slog.Error("failed to update webhook integration", "err", err)
		return ctx.JSON(500, "failed to update webhook integration")
	}
	return ctx.JSON(200, common.WebhookIntegrationDTO{
		ID:          webhookIntegration.ID.String(),
		Name:        *webhookIntegration.Name,
		Description: *webhookIntegration.Description,
		URL:         webhookIntegration.URL,
		Secret:      *webhookIntegration.Secret,
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}
func (w *WebhookIntegration) TestAndSave(ctx core.Context) error {
	var data struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		SbomEnabled bool   `json:"sbomEnabled"`
		VulnEnabled bool   `json:"vulnEnabled"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.URL == "" {
		return ctx.JSON(400, "url is required")
	}

	/* 	projectID := uuid.Nil
	   	if ok := core.HasProject(ctx); ok {
	   		project := core.GetProject(ctx)
	   		projectID = project.ID
	   	} */

	webhookIntegration := &models.WebhookIntegration{
		Name:        &data.Name,
		Description: &data.Description,
		URL:         data.URL,
		Secret:      &data.Secret,
		SbomEnabled: data.SbomEnabled,
		VulnEnabled: data.VulnEnabled,
		OrgID:       core.GetOrg(ctx).GetID(),
		/* 	ProjectID:   &projectID, */
	}

	if err := w.webhookRepository.Save(nil, webhookIntegration); err != nil {
		slog.Error("failed to save webhook integration", "err", err)
		return ctx.JSON(500, "failed to save webhook integration")
	}
	return ctx.JSON(200, common.WebhookIntegrationDTO{
		ID:          webhookIntegration.ID.String(),
		Name:        *webhookIntegration.Name,
		Description: *webhookIntegration.Description,
		URL:         webhookIntegration.URL,
		Secret:      *webhookIntegration.Secret,
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}

func (w *WebhookIntegration) HandleEvent(event any) error {
	return nil
}

func (w *WebhookIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	// Logic to determine if this integration wants to handle the webhook
	return true
}

func (w *WebhookIntegration) HandleWebhook(ctx core.Context) error {
	// Logic to handle the webhook
	return nil
}

func (w *WebhookIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// Logic to list organizations
	return nil, nil
}

func (w *WebhookIntegration) ListGroups(ctx core.Context, userID string, providerID string) ([]models.Project, error) {
	// Logic to list groups
	return nil, nil
}

func (w *WebhookIntegration) ListProjects(ctx core.Context, userID string, providerID string, groupID string) ([]models.Asset, error) {
	// Logic to list projects
	return nil, nil
}

func (w *WebhookIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	// Logic to list repositories
	return nil, nil
}

func (w *WebhookIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	// Logic to check access to external entity provider
	return false, nil
}

func (w *WebhookIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// Logic to get role in group
	return "", nil
}

func (w *WebhookIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// Logic to get role in project
	return "", nil
}

func (w *WebhookIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	// Logic to create an issue
	return nil
}

func (w *WebhookIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	// Logic to update an issue
	return nil
}

func (w *WebhookIntegration) GetUsers(org models.Org) []core.User {
	// Logic to get users in an organization
	return nil
}

func (w *WebhookIntegration) GetID() core.IntegrationID {
	// Return the integration ID for this webhook integration
	return core.WebhookIntegrationID
}
