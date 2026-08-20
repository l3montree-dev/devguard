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

type ModifiedRequirementLevel string

const (
	ModifiedRequirementLevelNotDefined ModifiedRequirementLevel = "X"
	ModifiedRequirementLevelNone       ModifiedRequirementLevel = "none"
	ModifiedRequirementLevelLow        ModifiedRequirementLevel = "low"
	ModifiedRequirementLevelHigh       ModifiedRequirementLevel = "high"
)

type ModifiedAttackVector string

const (
	MAVNetwork         ModifiedAttackVector = "network"
	MAVAdjacentNetwork ModifiedAttackVector = "adjacent"
	MAVLocal           ModifiedAttackVector = "local"
	MAVPhysical        ModifiedAttackVector = "physical"
	MAVNotDefined      ModifiedAttackVector = "X"
)

type ModifiedAttackComplexity string

const (
	MACLow        ModifiedAttackComplexity = "low"
	MACHigh       ModifiedAttackComplexity = "high"
	MACNotDefined ModifiedAttackComplexity = "X"
)

type ModifiedPrivilegesRequired string

const (
	MPRNone       ModifiedPrivilegesRequired = "none"
	MPRLow        ModifiedPrivilegesRequired = "low"
	MPRHigh       ModifiedPrivilegesRequired = "high"
	MPRNotDefined ModifiedPrivilegesRequired = "X"
)

type ModifiedScope string

const (
	MSUnchanged  ModifiedScope = "unchanged"
	MSChanged    ModifiedScope = "changed"
	MSNotDefined ModifiedScope = "X"
)

type ModifiedUserInteraction string

const (
	MUINotDefined ModifiedUserInteraction = "X"
	MUINone       ModifiedUserInteraction = "none"
	MUIRequired   ModifiedUserInteraction = "required"
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

	AvailabilityRequirement    RequirementLevel           `json:"availabilityRequirement"`
	IntegrityRequirement       RequirementLevel           `json:"integrityRequirement"`
	ConfidentialityRequirement RequirementLevel           `json:"confidentialityRequirement"`
	ModifiedAttackVector       ModifiedAttackVector       `json:"modifiedAttackVector"`
	ModifiedAttackComplexity   ModifiedAttackComplexity   `json:"modifiedAttackComplexity"`
	ModifiedPrivilegesRequired ModifiedPrivilegesRequired `json:"modifiedPrivilegesRequired"`
	ModifiedScope              ModifiedScope              `json:"modifiedScope"`
	ModifiedUserInteraction    ModifiedUserInteraction    `json:"modifiedUserInteraction"`
	ModifiedConfidentiality    ModifiedRequirementLevel   `json:"modifiedConfidentiality"`
	ModifiedIntegrity          ModifiedRequirementLevel   `json:"modifiedIntegrity"`
	ModifiedAvailability       ModifiedRequirementLevel   `json:"modifiedAvailability"`

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

	State string `json:"state"`
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

	Importance int `json:"importance"`

	ConfidentialityRequirement string  `json:"confidentialityRequirement" validate:"required,oneof=low medium high"`
	IntegrityRequirement       string  `json:"integrityRequirement" validate:"required,oneof=low medium high"`
	AvailabilityRequirement    string  `json:"availabilityRequirement" validate:"required,oneof=low medium high"`
	ModifiedAttackVector       string  `json:"modifiedAttackVector" validate:"omitempty,oneof=X network adjacent local physical"`
	ModifiedAttackComplexity   string  `json:"modifiedAttackComplexity" validate:"omitempty,oneof=X low high"`
	ModifiedPrivilegesRequired string  `json:"modifiedPrivilegesRequired" validate:"omitempty,oneof=X none low high"`
	ModifiedScope              string  `json:"modifiedScope" validate:"omitempty,oneof=X unchanged changed"`
	ModifiedUserInteraction    string  `json:"modifiedUserInteraction" validate:"omitempty,oneof=X none required"`
	ModifiedConfidentiality    string  `json:"modifiedConfidentiality" validate:"omitempty,oneof=X none low high"`
	ModifiedIntegrity          string  `json:"modifiedIntegrity" validate:"omitempty,oneof=X none low high"`
	ModifiedAvailability       string  `json:"modifiedAvaiModifiedAvailability" validate:"omitempty,oneof=X none low high"`
	RepositoryProvider         *string `json:"repositoryProvider" validate:"omitempty,oneof=github gitlab"` // either null or github or gitlab, etc.
}

type AssetPatchRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`

	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`
	EnableTicketRange            *bool    `json:"enableTicketRange"`

	CentralDependencyVulnManagement *bool `json:"centralDependencyVulnManagement"`

	ConfidentialityRequirement *RequirementLevel           `json:"confidentialityRequirement" validate:"omitempty,oneof=low medium high"`
	IntegrityRequirement       *RequirementLevel           `json:"integrityRequirement" validate:"omitempty,oneof=low medium high"`
	AvailabilityRequirement    *RequirementLevel           `json:"availabilityRequirement" validate:"omitempty,oneof=low medium high"`
	ModifiedAttackVector       *ModifiedAttackVector       `json:"modifiedAttackVector" validate:"omitempty,oneof=X network adjacent local physical"`
	ModifiedAttackComplexity   *ModifiedAttackComplexity   `json:"modifiedAttackComplexity" validate:"omitempty,oneof=X low high"`
	ModifiedPrivilegesRequired *ModifiedPrivilegesRequired `json:"modifiedPrivilegesRequired" validate:"omitempty,oneof=X none low high"`
	ModifiedScope              *ModifiedScope              `json:"modifiedScope" validate:"omitempty,oneof=X unchanged changed"`
	ModifiedUserInteraction    *ModifiedUserInteraction    `json:"modifiedUserInteraction" validate:"omitempty,oneof=X none required"`
	ModifiedConfidentiality    *ModifiedRequirementLevel   `json:"modifiedConfidentiality" validate:"omitempty,oneof=X none low high"`
	ModifiedIntegrity          *ModifiedRequirementLevel   `json:"modifiedIntegrity" validate:"omitempty,oneof=X none low high"`
	ModifiedAvailability       *ModifiedRequirementLevel   `json:"modifiedAvaiModifiedAvailability" validate:"omitempty,oneof=X none low high"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	ConfigFiles *map[string]any `json:"configFiles"`

	VulnAutoReopenAfterDays *int `json:"vulnAutoReopenAfterDays"`

	WebhookSecret *string `json:"webhookSecret"`

	RepositoryProvider *string `json:"repositoryProvider" validate:"omitempty,oneof=github gitlab"` // either null or github or gitlab, etc.
	IsPublic           *bool   `json:"isPublic"`
	ParanoidMode       *bool   `json:"paranoidMode"`

	SharesInformation *bool `json:"sharesInformation"`
}
