// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package controllers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
)

type WebhookController struct {
	webhookRepository shared.WebhookIntegrationRepository
}

var _ shared.ThirdPartyIntegration = &WebhookController{}

func NewWebhookController(db shared.DB) *WebhookController {
	webhookRepository := repositories.NewWebhookRepository(db)
	return &WebhookController{
		webhookRepository: webhookRepository,
	}
}

// @Summary Delete webhook integration
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Param id path string true "Webhook ID"
// @Success 200
// @Router /webhooks/{id} [delete]
func (w *WebhookController) Delete(ctx shared.Context) error {
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

func (w *WebhookController) CompareIssueStatesAndResolveDifferences(asset models.Asset, vulnsWithTickets []models.DependencyVuln) error {
	// Webhook integration does not support issue tracking
	return nil
}

// @Summary Update webhook integration
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /webhooks [put]
func (w *WebhookController) Update(ctx shared.Context) error {
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
	return ctx.JSON(200, dtos.WebhookIntegrationDTO{
		ID:          webhookIntegration.ID.String(),
		Name:        *webhookIntegration.Name,
		Description: *webhookIntegration.Description,
		URL:         webhookIntegration.URL,
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}
// @Summary Create webhook integration
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /webhooks [post]
func (w *WebhookController) Save(ctx shared.Context) error {
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

	ok := shared.HasProject(ctx)
	if ok {
		projID := shared.GetProject(ctx).GetID()
		projectID = &projID
	}

	webhookIntegration := &models.WebhookIntegration{
		Name:        &data.Name,
		Description: &data.Description,
		URL:         data.URL,
		Secret:      &data.Secret,
		SbomEnabled: data.SbomEnabled,
		VulnEnabled: data.VulnEnabled,
		OrgID:       shared.GetOrg(ctx).GetID(),
		ProjectID:   projectID, // Set project ID if available
	}

	if err := w.webhookRepository.Save(nil, webhookIntegration); err != nil {
		slog.Error("failed to save webhook integration", "err", err)
		return ctx.JSON(500, "failed to save webhook integration")
	}
	return ctx.JSON(200, dtos.WebhookIntegrationDTO{
		ID:          webhookIntegration.ID.String(),
		Name:        *webhookIntegration.Name,
		Description: *webhookIntegration.Description,
		URL:         webhookIntegration.URL,
		SbomEnabled: webhookIntegration.SbomEnabled,
		VulnEnabled: webhookIntegration.VulnEnabled,
	})
}

// @Summary Test webhook integration
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "Test webhook data"
// @Success 200 {object} object{message=string,payloadType=string}
// @Router /webhooks/test [post]
func (w *WebhookController) Test(ctx shared.Context) error {
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
	var payloadType services.TestPayloadType
	switch data.PayloadType {
	case "empty":
		payloadType = services.TestPayloadTypeEmpty
	case "sampleSbom":
		payloadType = services.TestPayloadTypeSampleSBOM
	case "sampleDependencyVulns":
		payloadType = services.TestPayloadTypeSampleDependencyVulns
	case "sampleFirstPartyVulns":
		payloadType = services.TestPayloadTypeSampleFirstPartyVulns
	default:
		return ctx.JSON(400, map[string]string{
			"error": "Invalid payload type. Supported types: empty, sampleSbom, sampleDependencyVulns, sampleFirstPartyVulns",
		})
	}

	// Create example objects for testing
	org := shared.ToOrgObject(shared.GetOrg(ctx))

	// For assets and projects, we'll use example data if not available in context
	var project shared.ProjectObject
	var asset shared.AssetObject
	var assetVersion shared.AssetVersionObject

	if shared.HasProject(ctx) {
		project = shared.ToProjectObject(shared.GetProject(ctx))
	} else {
		// Create example project data
		project = shared.ProjectObject{
			ID:          uuid.New(),
			Name:        "Example Project",
			Slug:        "example-project",
			Description: "Example project for webhook testing",
			IsPublic:    false,
			Type:        "application",
		}
	}

	// Create example asset and asset version data for testing
	asset = shared.AssetObject{
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

	assetVersion = shared.AssetVersionObject{
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

	client := services.NewWebhookService(data.URL, secret)

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

func (w *WebhookController) HandleEvent(event any) error {

	switch event := event.(type) {
	case shared.SBOMCreatedEvent:
		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.SbomEnabled {
				//send sbom
				if err := client.SendSBOM(*event.SBOM, event.Org, event.Project, event.Asset, event.AssetVersion, event.Artifact); err != nil {
					slog.Error("failed to send SBOM to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("SBOM sent to webhook", "webhookID", webhook.ID)
			}
		}
	case shared.FirstPartyVulnsDetectedEvent:

		vulns := event.Vulns.([]dtos.FirstPartyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendFirstPartyVulnerabilities(vulns, event.Org, event.Project, event.Asset, event.AssetVersion); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("Vulnerability sent to webhook", "webhookID", webhook.ID)
			}
		}

	case shared.DependencyVulnsDetectedEvent:

		vulns := event.Vulns.([]dtos.DependencyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendDependencyVulnerabilities(vulns, event.Org, event.Project, event.Asset, event.AssetVersion, event.Artifact); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				}
				slog.Info("Vulnerability sent to webhook", "webhookID", webhook.ID)
			}
		}
	}

	return nil
}

func (w *WebhookController) CreateLabels(ctx context.Context, asset models.Asset) error {
	// Webhook integration does not support creating labels
	return nil
}

func (w *WebhookController) WantsToHandleWebhook(ctx shared.Context) bool {
	// Logic to determine if this integration wants to handle the webhook
	return true
}

func (w *WebhookController) HandleWebhook(ctx shared.Context) error {
	// Logic to handle the webhook
	return nil
}

func (w *WebhookController) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	// Logic to list organizations
	return nil, nil
}

func (w *WebhookController) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
	// Logic to list groups
	return nil, nil, nil
}

func (w *WebhookController) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
	// Logic to list projects
	return nil, nil, nil
}

func (w *WebhookController) ListRepositories(ctx shared.Context) ([]dtos.GitRepository, error) {
	// Logic to list repositories
	return nil, nil
}

func (w *WebhookController) HasAccessToExternalEntityProvider(ctx shared.Context, externalEntityProviderID string) (bool, error) {
	// Logic to check access to external entity provider
	return false, nil
}

func (w *WebhookController) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// Logic to get role in group
	return "", nil
}

func (w *WebhookController) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// Logic to get role in project
	return "", nil
}

func (w *WebhookController) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	// Logic to create an issue
	return nil
}

func (w *WebhookController) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln) error {
	// Logic to update an issue
	return nil
}

func (w *WebhookController) GetUsers(org models.Org) []dtos.UserDTO {
	// Logic to get users in an organization
	return nil
}

func (w *WebhookController) GetID() shared.IntegrationID {
	// Return the integration ID for this webhook integration
	return shared.WebhookIntegrationID
}
