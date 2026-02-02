package models

import (
	"time"

	"github.com/google/uuid"

	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
)

type AssetType string

const (
	AssetTypeApplication    AssetType = "application"
	AssetTypeInfrastructure AssetType = "infrastructure"
)

type Asset struct {
	Model
	Name                         string                `json:"name" gorm:"type:text"`
	Avatar                       *string               `json:"avatar" gorm:"type:text"`
	Slug                         string                `json:"slug" gorm:"type:text;uniqueIndex:idx_app_project_slug;not null;"`
	ProjectID                    uuid.UUID             `json:"projectId" gorm:"uniqueIndex:idx_app_project_slug;not null;type:uuid;"`
	Description                  string                `json:"description" gorm:"type:text"`
	Type                         AssetType             `json:"type" gorm:"type:text;not null;"`
	AssetVersions                []AssetVersion        `json:"refs" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	Project                      Project               `json:"project" gorm:"foreignKey:ProjectID;references:ID;constraint:OnDelete:CASCADE;"`
	Importance                   int                   `json:"importance" gorm:"default:1;"`
	ReachableFromInternet        bool                  `json:"reachableFromInternet" gorm:"default:false;"`
	ConfidentialityRequirement   dtos.RequirementLevel `json:"confidentialityRequirement" gorm:"default:'high';not null;type:text;"`
	IntegrityRequirement         dtos.RequirementLevel `json:"integrityRequirement" gorm:"default:'high';not null;type:text;"`
	AvailabilityRequirement      dtos.RequirementLevel `json:"availabilityRequirement" gorm:"default:'high';not null;type:text;"`
	RepositoryID                 *string               `json:"repositoryId" gorm:"type:text;"` // the id will be prefixed with the provider name, e.g. github:<github app installation id>:123456
	RepositoryName               *string               `json:"repositoryName" gorm:"type:text;"`
	CVSSAutomaticTicketThreshold *float64              `json:"cvssAutomaticTicketThreshold" gorm:"type:decimal(4,2);"`
	RiskAutomaticTicketThreshold *float64              `json:"riskAutomaticTicketThreshold" gorm:"type:decimal(4,2);"`
	// Auto-reopen configuration - number of days after which closed/accepted vulnerabilities should be reopened
	VulnAutoReopenAfterDays  *int                `json:"vulnAutoReopenAfterDays" gorm:"type:integer;"`
	SigningPubKey            *string             `json:"signingPubKey" gorm:"type:text;"`
	ConfigFiles              databasetypes.JSONB `json:"configFiles" gorm:"type:jsonb"`
	WebhookSecret            *uuid.UUID          `json:"webhookSecret" gorm:"type:uuid;default:gen_random_uuid();"`
	ExternalEntityID         *string             `json:"externalEntityId" gorm:"uniqueIndex:asset_unique_external_entity;type:text"`
	ExternalEntityProviderID *string             `json:"externalEntityProviderId" gorm:"uniqueIndex:asset_unique_external_entity;type:text"`
	RepositoryProvider       *string             `json:"repositoryProvider" gorm:"type:text;"`
	Metadata                 databasetypes.JSONB `json:"metadata" gorm:"column:metadata;type:jsonb;"`
	IsPublic                 bool                `json:"isPublic" gorm:"default:false;not null;"`
	ParanoidMode             bool                `json:"paranoidMode" gorm:"default:false;not null;"`
	SharesInformation        bool                `json:"shareInformation" gorm:"default:false;not null;"`

	PipelineLastRun time.Time `json:"pipelineLastRun" gorm:"type:timestamp with time zone;"`
	PipelineError   *string   `json:"pipelineError" gorm:"type:text;"`
}

func (m *Asset) UpstreamState() dtos.UpstreamState {
	if m.ParanoidMode {
		return dtos.UpstreamStateExternal
	}
	return dtos.UpstreamStateExternalAccepted
}

func (m Asset) TableName() string {
	return "assets"
}

func (m *Asset) Same(other *Asset) bool {
	if m.ExternalEntityID == nil || m.ExternalEntityProviderID == nil {
		return m.ID != uuid.Nil && m.ID == other.ID
	}

	return *m.ExternalEntityID == *other.ExternalEntityID &&
		*m.ExternalEntityProviderID == *other.ExternalEntityProviderID
}

func (m *Asset) GetSlug() string {
	return m.Slug
}
func (m *Asset) SetSlug(slug string) {
	m.Slug = slug
}

func (m *Asset) DesiredUpstreamStateForEvents() dtos.UpstreamState {
	if m.ParanoidMode {
		return dtos.UpstreamStateExternal
	}
	return dtos.UpstreamStateExternalAccepted
}
