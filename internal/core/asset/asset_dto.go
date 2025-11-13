package asset

import (
	"time"

	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LookupResponse struct {
	Org     string `json:"org"`
	Project string `json:"project"`
	Asset   string `json:"asset"`
	Link    string `json:"link"`
}

type changeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type inviteToAssetRequest struct {
	Ids []string `json:"ids" validate:"required"`
}

type AssetDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Avatar      *string   `json:"avatar,omitempty"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	ProjectID   uuid.UUID `json:"projectId"`

	AvailabilityRequirement    models.RequirementLevel `json:"availabilityRequirement"`
	IntegrityRequirement       models.RequirementLevel `json:"integrityRequirement"`
	ConfidentialityRequirement models.RequirementLevel `json:"confidentialityRequirement"`
	ReachableFromInternet      bool                    `json:"reachableFromInternet"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	LastSecretScan               *time.Time `json:"lastSecretScan"`
	LastSastScan                 *time.Time `json:"lastSastScan"`
	LastScaScan                  *time.Time `json:"lastScaScan"`
	LastIacScan                  *time.Time `json:"lastIacScan"`
	LastContainerScan            *time.Time `json:"lastContainerScan"`
	LastDastScan                 *time.Time `json:"lastDastScan"`
	SigningPubKey                *string    `json:"signingPubKey"`
	EnableTicketRange            bool       `json:"enableTicketRange"`
	CVSSAutomaticTicketThreshold *float64   `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64   `json:"riskAutomaticTicketThreshold"`
	VulnAutoReopenAfterDays      *int       `json:"vulnAutoReopenAfterDays"`

	AssetVersions []models.AssetVersion `json:"refs"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"`

	RepositoryProvider *string `json:"repositoryProvider,omitempty"`
	IsPublic           bool    `json:"isPublic"`
	ParanoidMode       bool    `json:"paranoidMode"`
	SharesInformation  bool    `json:"sharesInformation"`
}

type AssetWithSecretsDTO struct {
	AssetDTO
	BadgeSecret   *uuid.UUID `json:"badgeSecret"`
	WebhookSecret *uuid.UUID `json:"webhookSecret"`
}

type AssetDetailsDTO struct {
	AssetDTO
	Members []core.User `json:"members"`
}

type AssetDetailsWithSecretsDTO struct {
	AssetWithSecretsDTO
	Members []core.User `json:"members"`
}

func ToDTOs(assets []models.Asset) []AssetDTO {
	assetDTOs := make([]AssetDTO, len(assets))
	for i, asset := range assets {
		assetDTOs[i] = ToDTO(asset)
	}
	return assetDTOs
}

func ToDetailsDTO(asset models.Asset, members []core.User) AssetDetailsDTO {
	return AssetDetailsDTO{
		AssetDTO: ToDTO(asset),
		Members:  members,
	}
}

func ToDetailsDTOWithSecrets(asset models.Asset, members []core.User) AssetDetailsWithSecretsDTO {
	return AssetDetailsWithSecretsDTO{
		AssetWithSecretsDTO: toDTOWithSecrets(asset),
		Members:             members,
	}
}

func ToDTO(asset models.Asset) AssetDTO {
	return AssetDTO{
		ID:          asset.ID,
		Name:        asset.Name,
		Avatar:      asset.Avatar,
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
		RepositoryProvider:       asset.RepositoryProvider,
		IsPublic:                 asset.IsPublic,
		ParanoidMode:             asset.ParanoidMode,
		SharesInformation:        asset.SharesInformation,
	}
}

func toDTOWithSecrets(asset models.Asset) AssetWithSecretsDTO {
	return AssetWithSecretsDTO{
		AssetDTO:      ToDTO(asset),
		BadgeSecret:   asset.BadgeSecret,
		WebhookSecret: asset.WebhookSecret,
	}
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

	ConfidentialityRequirement string  `json:"confidentialityRequirement" validate:"required"`
	IntegrityRequirement       string  `json:"integrityRequirement" validate:"required"`
	AvailabilityRequirement    string  `json:"availabilityRequirement" validate:"required"`
	RepositoryProvider         *string `json:"repositoryProvider" validate:"omitempty,oneof=github gitlab"` // either null or github or gitlab, etc.
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
		RepositoryProvider:         a.RepositoryProvider,
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
	EnableTicketRange            *bool    `json:"enableTicketRange"`

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

	RepositoryProvider *string `json:"repositoryProvider" validate:"omitempty,oneof=github gitlab"` // either null or github or gitlab, etc.
	IsPublic           *bool   `json:"isPublic"`
	ParanoidMode       *bool   `json:"paranoidMode"`

	SharesInformation *bool `json:"sharesInformation"`
}

func (assetPatch *PatchRequest) applyToModel(asset *models.Asset) bool {
	updated := false
	if assetPatch.Name != nil {
		updated = true
		asset.Name = *assetPatch.Name
		asset.Slug = slug.Make(*assetPatch.Name)
	}

	if assetPatch.SharesInformation != nil {
		updated = true
		asset.SharesInformation = *assetPatch.SharesInformation
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

	if assetPatch.RepositoryProvider != nil && *assetPatch.RepositoryProvider != "" {
		updated = true
		if *assetPatch.RepositoryProvider == "" {
			asset.RepositoryProvider = nil
		} else {
			asset.RepositoryProvider = assetPatch.RepositoryProvider
		}
	}

	if assetPatch.IsPublic != nil {
		updated = true
		asset.IsPublic = *assetPatch.IsPublic
	}

	if assetPatch.ParanoidMode != nil {
		updated = true
		asset.ParanoidMode = *assetPatch.ParanoidMode
	}

	return updated
}
