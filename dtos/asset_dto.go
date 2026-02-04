package dtos

import (
	"time"

	"github.com/google/uuid"
)

type RequirementLevel string

const (
	RequirementLevelLow    RequirementLevel = "low"
	RequirementLevelMedium RequirementLevel = "medium"
	RequirementLevelHigh   RequirementLevel = "high"
)

type LookupResponse struct {
	Org     string `json:"org"`
	Project string `json:"project"`
	Asset   string `json:"asset"`
	Link    string `json:"link"`
}

type AssetChangeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type AssetInviteToAssetRequest struct {
	Ids []string `json:"ids" validate:"required"`
}

type AssetDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Avatar      *string   `json:"avatar,omitempty"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	ProjectID   uuid.UUID `json:"projectId"`

	AvailabilityRequirement    RequirementLevel `json:"availabilityRequirement"`
	IntegrityRequirement       RequirementLevel `json:"integrityRequirement"`
	ConfidentialityRequirement RequirementLevel `json:"confidentialityRequirement"`
	ReachableFromInternet      bool             `json:"reachableFromInternet"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	SigningPubKey                *string  `json:"signingPubKey"`
	EnableTicketRange            bool     `json:"enableTicketRange"`
	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`
	VulnAutoReopenAfterDays      *int     `json:"vulnAutoReopenAfterDays"`

	AssetVersions []AssetVersionDTO `json:"refs"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"`

	RepositoryProvider              *string   `json:"repositoryProvider,omitempty"`
	IsPublic                        bool      `json:"isPublic"`
	ParanoidMode                    bool      `json:"paranoidMode"`
	SharesInformation               bool      `json:"sharesInformation"`
	CentralDependencyVulnManagement bool      `json:"centralDependencyVulnManagement"`
	PipelineLastRun                 time.Time `json:"pipelineLastRun"`
	PipelineError                   *string   `json:"pipelineError,omitempty"`
}

type AssetWithSecretsDTO struct {
	AssetDTO
	WebhookSecret *uuid.UUID `json:"webhookSecret"`
}

type AssetDetailsDTO struct {
	AssetDTO
	Members []UserDTO `json:"members"`
}

type AssetDetailsWithSecretsDTO struct {
	AssetWithSecretsDTO
	Members []UserDTO `json:"members"`
}

type AssetCreateRequest struct {
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

type AssetPatchRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`

	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`
	EnableTicketRange            *bool    `json:"enableTicketRange"`

	CentralDependencyVulnManagement *bool `json:"centralDependencyVulnManagement"`

	ReachableFromInternet *bool `json:"reachableFromInternet"`

	ConfidentialityRequirement *RequirementLevel `json:"confidentialityRequirement"`
	IntegrityRequirement       *RequirementLevel `json:"integrityRequirement"`
	AvailabilityRequirement    *RequirementLevel `json:"availabilityRequirement"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	ConfigFiles *map[string]any `json:"configFiles"`

	VulnAutoReopenAfterDays *int `json:"vulnAutoReopenAfterDays"`

	WebhookSecret *string `json:"webhookSecret"`

	RepositoryProvider *string `json:"repositoryProvider" validate:"omitempty,oneof=github gitlab"` // either null or github or gitlab, etc.
	IsPublic           *bool   `json:"isPublic"`
	ParanoidMode       *bool   `json:"paranoidMode"`

	SharesInformation *bool `json:"sharesInformation"`

	KeepOriginalSbomRootComponent *bool `json:"keepOriginalSbomRootComponent"`
}
