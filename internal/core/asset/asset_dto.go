package asset

import (
	"time"

	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LookupResponse struct {
	Org     string `json:"org"`
	Project string `json:"project"`
	Asset   string `json:"asset"`
	Link    string `json:"link"`
}

type AssetDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	ProjectID   uuid.UUID `json:"projectId"`

	AvailabilityRequirement    models.RequirementLevel `json:"availabilityRequirement"`
	IntegrityRequirement       models.RequirementLevel `json:"integrityRequirement"`
	ConfidentialityRequirement models.RequirementLevel `json:"confidentialityRequirement"`
	ReachableFromInternet      bool                    `json:"reachableFromInternet"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	LastSecretScan    *time.Time `json:"lastSecretScan"`
	LastSastScan      *time.Time `json:"lastSastScan"`
	LastScaScan       *time.Time `json:"lastScaScan"`
	LastIacScan       *time.Time `json:"lastIacScan"`
	LastContainerScan *time.Time `json:"lastContainerScan"`
	LastDastScan      *time.Time `json:"lastDastScan"`

	SigningPubKey *string `json:"signingPubKey"`

	EnableTicketRange            bool     `json:"enableTicketRange"`
	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`

	VulnAutoReopenAfterDays *int `json:"vulnAutoReopenAfterDays"`

	BadgeSecret   *uuid.UUID `json:"badgeSecret"`
	WebhookSecret *uuid.UUID `json:"webhookSecret"`

	AssetVersions []models.AssetVersion `json:"refs"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"`
}

func toDTOs(assets []models.Asset) []AssetDTO {
	assetDTOs := make([]AssetDTO, len(assets))
	for i, asset := range assets {
		assetDTOs[i] = toDTO(asset)
	}
	return assetDTOs
}

func toDTO(asset models.Asset) AssetDTO {
	return AssetDTO{
		ID:          asset.ID,
		Name:        asset.Name,
		Slug:        asset.Slug,
		Description: asset.Description,
		ProjectID:   asset.ProjectID,

		AvailabilityRequirement:    asset.AvailabilityRequirement,
		IntegrityRequirement:       asset.IntegrityRequirement,
		ConfidentialityRequirement: asset.ConfidentialityRequirement,
		ReachableFromInternet:      asset.ReachableFromInternet,

		RepositoryID:   asset.RepositoryID,
		RepositoryName: asset.RepositoryName,

		SigningPubKey: asset.SigningPubKey,

		CVSSAutomaticTicketThreshold: asset.CVSSAutomaticTicketThreshold,
		RiskAutomaticTicketThreshold: asset.RiskAutomaticTicketThreshold,

		VulnAutoReopenAfterDays: asset.VulnAutoReopenAfterDays,

		AssetVersions: asset.AssetVersions,

		ExternalEntityProviderID: asset.ExternalEntityProviderID,
		ExternalEntityID:         asset.ExternalEntityID,
	}
}

func toDTOWithSecrets(asset models.Asset) AssetDTO {
	assetDTO := toDTO(asset)
	assetDTO.BadgeSecret = asset.BadgeSecret
	assetDTO.WebhookSecret = asset.WebhookSecret

	return assetDTO
}

type createRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`

	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`
	EnableTicketRange            bool     `json:"enableTicketRange"`

	CentralDependencyVulnManagement bool `json:"centralDependencyVulnManagement"`

	Importance            int  `json:"importance"`
	ReachableFromInternet bool `json:"reachableFromInternet"`

	ConfidentialityRequirement string `json:"confidentialityRequirement" validate:"required"`
	IntegrityRequirement       string `json:"integrityRequirement" validate:"required"`
	AvailabilityRequirement    string `json:"availabilityRequirement" validate:"required"`
}

func sanitizeRequirementLevel(level string) models.RequirementLevel {
	switch level {
	case "low", "medium", "high":
		return models.RequirementLevel(level)
	default:
		return "medium"
	}
}

func (a *createRequest) toModel(projectID uuid.UUID) models.Asset {
	asset := models.Asset{Name: a.Name,
		Slug:        slug.Make(a.Name),
		ProjectID:   projectID,
		Description: a.Description,

		CentralDependencyVulnManagement: a.CentralDependencyVulnManagement,

		Importance:            a.Importance,
		ReachableFromInternet: a.ReachableFromInternet,

		ConfidentialityRequirement: sanitizeRequirementLevel(a.ConfidentialityRequirement),
		IntegrityRequirement:       sanitizeRequirementLevel(a.IntegrityRequirement),
		AvailabilityRequirement:    sanitizeRequirementLevel(a.AvailabilityRequirement),
	}

	if a.EnableTicketRange {
		asset.CVSSAutomaticTicketThreshold = a.CVSSAutomaticTicketThreshold
		asset.RiskAutomaticTicketThreshold = a.RiskAutomaticTicketThreshold
	}

	return asset
}

type PatchRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`

	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`
	EnableTicketRange            bool     `json:"enableTicketRange"`

	CentralDependencyVulnManagement *bool `json:"centralDependencyVulnManagement"`

	ReachableFromInternet *bool `json:"reachableFromInternet"`

	ConfidentialityRequirement *models.RequirementLevel `json:"confidentialityRequirement"`
	IntegrityRequirement       *models.RequirementLevel `json:"integrityRequirement"`
	AvailabilityRequirement    *models.RequirementLevel `json:"availabilityRequirement"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	ConfigFiles *map[string]any `json:"configFiles"`

	VulnAutoReopenAfterDays *int `json:"vulnAutoReopenAfterDays"`

	WebhookSecret *string `json:"webhookSecret"`
	BadgeSecret   *string `json:"badgeSecret"`
}

func (assetPatch *PatchRequest) applyToModel(asset *models.Asset) bool {
	updated := false
	if assetPatch.Name != nil {
		updated = true
		asset.Name = *assetPatch.Name
		asset.Slug = slug.Make(*assetPatch.Name)
	}

	if assetPatch.Description != nil {
		updated = true
		asset.Description = *assetPatch.Description
	}

	if assetPatch.CentralDependencyVulnManagement != nil {
		updated = true
		asset.CentralDependencyVulnManagement = *assetPatch.CentralDependencyVulnManagement
	}

	if assetPatch.ReachableFromInternet != nil {
		updated = true
		asset.ReachableFromInternet = *assetPatch.ReachableFromInternet
	}

	if assetPatch.RepositoryID != nil {
		updated = true
		if *assetPatch.RepositoryID == "" {
			asset.RepositoryID = nil
		} else {
			asset.RepositoryID = assetPatch.RepositoryID
		}
	}

	if assetPatch.RepositoryName != nil {
		updated = true
		if *assetPatch.RepositoryName == "" {
			asset.RepositoryName = nil
		} else {
			asset.RepositoryName = assetPatch.RepositoryName
		}
	}

	if assetPatch.ConfigFiles != nil {
		updated = true
		asset.ConfigFiles = *assetPatch.ConfigFiles
	}

	if assetPatch.WebhookSecret != nil {
		updated = true

		if *assetPatch.WebhookSecret == "" {
			asset.WebhookSecret = nil
		}

		webhookUUID, err := uuid.Parse(*assetPatch.WebhookSecret)
		if err == nil {
			asset.WebhookSecret = &webhookUUID

		}
	}

	if assetPatch.BadgeSecret != nil {
		updated = true

		if *assetPatch.BadgeSecret == "" {
			asset.BadgeSecret = nil
		}

		badgeUUID, err := uuid.Parse(*assetPatch.BadgeSecret)

		if err == nil {
			asset.BadgeSecret = &badgeUUID
		}
	}

	if assetPatch.VulnAutoReopenAfterDays != nil {
		updated = true
		asset.VulnAutoReopenAfterDays = assetPatch.VulnAutoReopenAfterDays
	}

	return updated
}
