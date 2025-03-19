package models

import (
	"time"

	"github.com/google/uuid"
)

type AssetType string

const (
	AssetTypeApplication    AssetType = "application"
	AssetTypeInfrastructure AssetType = "infrastructure"
)

type RequirementLevel string

const (
	RequirementLevelLow    RequirementLevel = "low"
	RequirementLevelMedium RequirementLevel = "medium"
	RequirementLevelHigh   RequirementLevel = "high"
)

type Asset struct {
	Model
	Name string `json:"name" gorm:"type:text"`
	Slug string `json:"slug" gorm:"type:text;uniqueIndex:idx_app_project_slug;not null;"`

	CentralDependencyVulnManagement bool `json:"centralDependencyVulnManagement" gorm:"default:false;"`

	ProjectID   uuid.UUID `json:"projectId" gorm:"uniqueIndex:idx_app_project_slug;not null;type:uuid;"`
	Description string    `json:"description" gorm:"type:text"`

	Type AssetType `json:"type" gorm:"type:text;not null;"`

	AssetVersions []AssetVersion `json:"refs" gorm:"foreignKey:AssetID;references:ID;"`

	Importance            int  `json:"importance" gorm:"default:1;"`
	ReachableFromInternet bool `json:"reachableFromInternet" gorm:"default:false;"`

	ConfidentialityRequirement RequirementLevel `json:"confidentialityRequirement" gorm:"default:'high';not null;type:text;"`
	IntegrityRequirement       RequirementLevel `json:"integrityRequirement" gorm:"default:'high';not null;type:text;"`
	AvailabilityRequirement    RequirementLevel `json:"availabilityRequirement" gorm:"default:'high';not null;type:text;"`

	RepositoryID   *string `json:"repositoryId" gorm:"type:text;"` // the id will be prefixed with the provider name, e.g. github:<github app installation id>:123456
	RepositoryName *string `json:"repositoryName" gorm:"type:text;"`

	LastHistoryUpdate            *time.Time
	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold" gorm:"type:decimal(4,2);"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold" gorm:"type:decimal(4,2);"`

	LastSecretScan    *time.Time `json:"lastSecretScan"`
	LastSastScan      *time.Time `json:"lastSastScan"`
	LastScaScan       *time.Time `json:"lastScaScan"`
	LastIacScan       *time.Time `json:"lastIacScan"`
	LastContainerScan *time.Time `json:"lastContainerScan"`
	LastDastScan      *time.Time `json:"lastDastScan"`

	SigningPubKey *string `json:"signingPubKey" gorm:"type:text;"`
}

func (m Asset) TableName() string {
	return "assets"
}
