// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package webhook

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
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

	oldWebhookIntegration, err := w.webhookRepository.GetClientByIntegrationID(uuidID)
	if err != nil {
		slog.Error("failed to get webhook integration by ID", "err", err)
		return ctx.JSON(500, "failed to get webhook integration")
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
		OrgID:       oldWebhookIntegration.OrgID,
		ProjectID:   oldWebhookIntegration.ProjectID,
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
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}
func (w *WebhookIntegration) Save(ctx core.Context) error {
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

	var projectID *uuid.UUID

	ok := core.HasProject(ctx)
	if ok {
		projID := core.GetProject(ctx).GetID()
		projectID = &projID
	}

	webhookIntegration := &models.WebhookIntegration{
		Name:        &data.Name,
		Description: &data.Description,
		URL:         data.URL,
		Secret:      &data.Secret,
		SbomEnabled: data.SbomEnabled,
		VulnEnabled: data.VulnEnabled,
		OrgID:       core.GetOrg(ctx).GetID(),
		ProjectID:   projectID, // Set project ID if available
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
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}

func (w *WebhookIntegration) Test(ctx core.Context) error {
	var data struct {
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		PayloadType string `json:"payloadType"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.URL == "" {
		return ctx.JSON(400, "url is required")
	}

	// Default to empty payload if not specified
	if data.PayloadType == "" {
		data.PayloadType = "empty"
	}

	// Validate payload type
	var payloadType TestPayloadType
	switch data.PayloadType {
	case "empty":
		payloadType = TestPayloadTypeEmpty
	case "sampleSbom":
		payloadType = TestPayloadTypeSampleSBOM
	case "sampleDependencyVulns":
		payloadType = TestPayloadTypeSampleDependencyVulns
	case "sampleFirstPartyVulns":
		payloadType = TestPayloadTypeSampleFirstPartyVulns
	default:
		return ctx.JSON(400, map[string]string{
			"error": "Invalid payload type. Supported types: empty, sampleSbom, sampleDependencyVulns, sampleFirstPartyVulns",
		})
	}

	// Create example objects for testing
	org := core.ToOrgObject(core.GetOrg(ctx))

	// For assets and projects, we'll use example data if not available in context
	var project core.ProjectObject
	var asset core.AssetObject
	var assetVersion core.AssetVersionObject

	if core.HasProject(ctx) {
		project = core.ToProjectObject(core.GetProject(ctx))
	} else {
		// Create example project data
		project = core.ProjectObject{
			ID:          uuid.New(),
			Name:        "Example Project",
			Slug:        "example-project",
			Description: "Example project for webhook testing",
			IsPublic:    false,
			Type:        "application",
		}
	}

	// Create example asset and asset version data for testing
	asset = core.AssetObject{
		ID:                         uuid.New(),
		Name:                       "Example Asset",
		Slug:                       "example-asset",
		Description:                "Example asset for webhook testing",
		ProjectID:                  project.ID,
		AvailabilityRequirement:    "high",
		IntegrityRequirement:       "high",
		ConfidentialityRequirement: "high",
		ReachableFromInternet:      false,
	}

	assetVersion = core.AssetVersionObject{
		Name:          "example-version",
		AssetID:       asset.ID,
		Slug:          "example-version",
		DefaultBranch: true,
		Type:          "branch",
	}

	// Create webhook client and send test
	var secret *string
	if data.Secret != "" {
		secret = &data.Secret
	}

	client := NewWebhookClient(data.URL, secret)

	if err := client.SendTest(org, project, asset, assetVersion, payloadType); err != nil {
		slog.Error("failed to send test webhook", "err", err)
		return ctx.JSON(400, map[string]string{
			"error": fmt.Sprintf("Webhook test failed: %s", err.Error()),
		})
	}

	return ctx.JSON(200, map[string]string{
		"message":     "Test webhook sent successfully",
		"payloadType": data.PayloadType,
	})
}

func (w *WebhookIntegration) HandleEvent(event any) error {

	switch event := event.(type) {
	case core.SBOMCreatedEvent:

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := NewWebhookClient(webhook.URL, webhook.Secret)
			if webhook.SbomEnabled {
				//send sbom
				if err := client.SendSBOM(*event.SBOM, event.Org, event.Project, event.Asset, event.AssetVersion); err != nil {
					slog.Error("failed to send SBOM to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("SBOM sent to webhook", "webhookID", webhook.ID)
			}
		}
	case core.FirstPartyVulnsDetectedEvent:

		vulns := event.Vulns.([]vuln.FirstPartyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := NewWebhookClient(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendFirstPartyVulnerabilities(vulns, event.Org, event.Project, event.Asset, event.AssetVersion); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("Vulnerability sent to webhook", "webhookID", webhook.ID)
			}
		}

	case core.DependencyVulnsDetectedEvent:

		vulns := event.Vulns.([]vuln.DependencyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := NewWebhookClient(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendDependencyVulnerabilities(vulns, event.Org, event.Project, event.Asset, event.AssetVersion); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("Vulnerability sent to webhook", "webhookID", webhook.ID)
			}
		}
	}

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

func (w *WebhookIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []core.Role, error) {
	// Logic to list groups
	return nil, nil, nil
}

func (w *WebhookIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []core.Role, error) {
	// Logic to list projects
	return nil, nil, nil
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
