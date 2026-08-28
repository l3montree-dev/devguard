// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package controllers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
)

type WebhookController struct {
	webhookRepository shared.WebhookIntegrationRepository
}

var _ shared.ThirdPartyIntegration = &WebhookController{}

func NewWebhookController(webhookRepository shared.WebhookIntegrationRepository) *WebhookController {
	return &WebhookController{
		webhookRepository: webhookRepository,
	}
}

type WebhookSaveRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url" validate:"required"`
	Secret      string `json:"secret"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}

type WebhookUpdateRequest struct {
	ID string `json:"id"`
	WebhookSaveRequest
}

type WebhookTestRequest struct {
	URL         string `json:"url" validate:"required"`
	Secret      string `json:"secret"`
	PayloadType string `json:"payloadType"`
}

// @Summary Delete webhook integration (org)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param id path string true "Webhook ID"
// @Success 200
// @Router /organizations/{organization}/integrations/webhook/{id} [delete]
func (w *WebhookController) OrgDelete(ctx shared.Context) error {
	return w.Delete(ctx)
}

// @Summary Delete webhook integration (project)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param id path string true "Webhook ID"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/integrations/webhook/{id} [delete]
func (w *WebhookController) ProjectDelete(ctx shared.Context) error {
	return w.Delete(ctx)
}
func (w *WebhookController) Delete(ctx shared.Context) error {
	id := ctx.Param("id")
	if id == "" {
		return ctx.JSON(400, "id is required")
	}

	uuidID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, "invalid id format")
	}

	if err := w.webhookRepository.Delete(ctx.Request().Context(), nil, uuidID); err != nil {
		if shared.IsNotFound(err) {
			return ctx.JSON(404, "webhook integration not found")
		}
		slog.Error("failed to delete webhook integration", "err", err)
		return ctx.JSON(500, "failed to delete webhook integration")
	}
	return ctx.JSON(200, "Webhook integration deleted successfully")
}

func (w *WebhookController) CompareIssueStatesAndResolveDifferences(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) error {
	return nil
}

func (w *WebhookController) GetExcessTicketIDs(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) ([]string, error) {
	return nil, nil
}

// @Summary Update webhook integration (org)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param id path string true "Webhook ID"
// @Param body body controllers.WebhookUpdateRequest true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /organizations/{organization}/integrations/webhook/{id} [put]
func (w *WebhookController) OrgUpdate(ctx shared.Context) error {
	return w.Update(ctx)
}

// @Summary Update webhook integration (project)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param id path string true "Webhook ID"
// @Param body body controllers.WebhookUpdateRequest true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /organizations/{organization}/projects/{projectSlug}/integrations/webhook/{id} [put]
func (w *WebhookController) ProjectUpdate(ctx shared.Context) error {
	return w.Update(ctx)
}
func (w *WebhookController) Update(ctx shared.Context) error {
	var data WebhookUpdateRequest
	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if err := dtos.V.Struct(&data); err != nil {
		return ctx.JSON(400, "url is required")
	}

	uuidID, err := uuid.Parse(data.ID)
	if err != nil {
		return ctx.JSON(400, "invalid id format")
	}

	oldWebhookIntegration, err := w.webhookRepository.GetClientByIntegrationID(ctx.Request().Context(), nil, uuidID)
	if err != nil {
		if shared.IsNotFound(err) {
			return ctx.JSON(404, "webhook integration not found")
		}
		slog.Error("failed to get webhook integration by ID", "err", err)
		return ctx.JSON(500, "failed to get webhook integration")
	}

	webhookIntegration := &models.WebhookIntegration{
		Model: models.Model{
			ID:        uuidID,
			CreatedAt: oldWebhookIntegration.CreatedAt, // Save() writes every column, so carry this over or it resets to the zero time
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

	if err := w.webhookRepository.Save(ctx.Request().Context(), nil, webhookIntegration); err != nil {
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

// @Summary Create webhook integration (org)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body controllers.WebhookSaveRequest true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /organizations/{organization}/integrations/webhook/test-and-save [post]
func (w *WebhookController) OrgSave(ctx shared.Context) error {
	return w.Save(ctx)
}

// @Summary Create webhook integration (project)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body controllers.WebhookSaveRequest true "Webhook data"
// @Success 200 {object} dtos.WebhookIntegrationDTO
// @Router /organizations/{organization}/projects/{projectSlug}/integrations/webhook/test-and-save [post]
func (w *WebhookController) ProjectSave(ctx shared.Context) error {
	return w.Save(ctx)
}
func (w *WebhookController) Save(ctx shared.Context) error {
	var data WebhookSaveRequest
	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if err := dtos.V.Struct(&data); err != nil {
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

	if err := w.webhookRepository.Save(ctx.Request().Context(), nil, webhookIntegration); err != nil {
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

// @Summary Test webhook integration (org)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body controllers.WebhookTestRequest true "Test webhook data"
// @Success 200 {object} object{message=string,payloadType=string}
// @Router /organizations/{organization}/integrations/webhook/test [post]
func (w *WebhookController) OrgTest(ctx shared.Context) error {
	return w.Test(ctx)
}

// @Summary Test webhook integration (project)
// @Tags Webhooks
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body controllers.WebhookTestRequest true "Test webhook data"
// @Success 200 {object} object{message=string,payloadType=string}
// @Router /organizations/{organization}/projects/{projectSlug}/integrations/webhook/test [post]
func (w *WebhookController) ProjectTest(ctx shared.Context) error {
	return w.Test(ctx)
}
func (w *WebhookController) Test(ctx shared.Context) error {
	var data WebhookTestRequest
	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if err := dtos.V.Struct(&data); err != nil {
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
		ModifiedAttackVector:       "network",
		ModifiedAttackComplexity:   "low",
		ModifiedPrivilegesRequired: "none",
		ModifiedScope:              "changed",
		ModifiedUserInteraction:    "required",
		ModifiedConfidentiality:    "high",
		ModifiedIntegrity:          "high",
		ModifiedAvailability:       "high",
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

	if err := client.SendTest(ctx.Request().Context(), org, project, asset, assetVersion, payloadType); err != nil {
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

func (w *WebhookController) HandleEvent(ctx context.Context, event any, userAgent *string) error {

	switch event := event.(type) {
	case shared.SBOMCreatedEvent:
		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(ctx, nil, event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.SbomEnabled {
				//send sbom
				if err := client.SendSBOM(ctx, *event.SBOM, event.Org, event.Project, event.Asset, event.AssetVersion, event.Artifact); err != nil {
					slog.Error("failed to send SBOM to webhook", "webhookID", webhook.ID, "err", err)
				} else {
					slog.Info("webhook sent", "eventType", "sbom", "webhookID", webhook.ID, "org", event.Org.Name)
				}
			}
		}
	case shared.FirstPartyVulnsDetectedEvent:

		vulns := event.Vulns.([]dtos.FirstPartyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(ctx, nil, event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendFirstPartyVulnerabilities(ctx, vulns, event.Org, event.Project, event.Asset, event.AssetVersion); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				} else {
					slog.Info("webhook sent", "eventType", "firstPartyVulnerabilities", "webhookID", webhook.ID, "org", event.Org.Name)
				}
			}
		}

	case shared.DependencyVulnsDetectedEvent:

		vulns := event.Vulns.([]dtos.DependencyVulnDTO)

		webhooks, err := w.webhookRepository.FindByOrgIDAndProjectID(ctx, nil, event.Org.ID, event.Project.ID)
		if err != nil {
			slog.Error("failed to find webhooks", "err", err)
			return err
		}

		for _, webhook := range webhooks {
			client := services.NewWebhookService(webhook.URL, webhook.Secret)
			if webhook.VulnEnabled {
				//send vulnerability
				if err := client.SendDependencyVulnerabilities(ctx, vulns, event.Org, event.Project, event.Asset, event.AssetVersion, event.Artifact); err != nil {
					slog.Error("failed to send vulnerability to webhook", "webhookID", webhook.ID, "err", err)
				} else {
					slog.Info("webhook sent", "eventType", "dependencyVulnerabilities", "webhookID", webhook.ID, "org", event.Org.Name)
				}
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

// @Summary Handle an incoming third-party webhook
// @Tags Webhooks
// @Success 200
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

func (w *WebhookController) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// Logic to get role in group
	return "", nil
}

func (w *WebhookController) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// Logic to get role in project
	return "", nil
}

func (w *WebhookController) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string, userAgent *string) error {
	// Logic to create an issue
	return nil
}

func (w *WebhookController) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, userAgent *string) error {
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
