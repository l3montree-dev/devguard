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

	ProjectID   uuid.UUID `json:"projectId" gorm:"uniqueIndex:idx_app_project_slug;not null;type:uuid;"`
	Description string    `json:"description" gorm:"type:text"`
	Flaws       []Flaw    `json:"flaws" gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE;"`

	Type AssetType `json:"type" gorm:"type:text;not null;"`

	Importance            int  `json:"importance" gorm:"default:1;"`
	ReachableFromInternet bool `json:"reachableFromInternet" gorm:"default:false;"`

	ConfidentialityRequirement RequirementLevel `json:"confidentialityRequirement" gorm:"default:'high';not null;type:text;"`
	IntegrityRequirement       RequirementLevel `json:"integrityRequirement" gorm:"default:'high';not null;type:text;"`
	AvailabilityRequirement    RequirementLevel `json:"availabilityRequirement" gorm:"default:'high';not null;type:text;"`

	Components []ComponentDependency `json:"components" gorm:"hasMany;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	RepositoryID *string `json:"repositoryId" gorm:"type:text;"` // the id will be prefixed with the provider name, e.g. github:<github app installation id>:123456

	LastHistoryUpdate *time.Time

	LastSecretScan    *time.Time `json:"lastSecretScan"`
	LastSastScan      *time.Time `json:"lastSastScan"`
	LastScaScan       *time.Time `json:"lastScaScan"`
	LastIacScan       *time.Time `json:"lastIacScan"`
	LastContainerScan *time.Time `json:"lastContainerScan"`
	LastDastScan      *time.Time `json:"lastDastScan"`
}

func (m Asset) TableName() string {
	return "assets"
}

func (m Asset) GetCurrentAssetComponents() []ComponentDependency {
	AssetComponents := make([]ComponentDependency, 0)
	for _, assetComponent := range m.Components {
		if assetComponent.AssetSemverEnd == nil {
			AssetComponents = append(AssetComponents, assetComponent)
		}
	}
	return AssetComponents
}
