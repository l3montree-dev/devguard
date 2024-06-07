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

	Components []AssetComponent `json:"components" gorm:"hasMany;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	Version             string    `json:"version" gorm:"type:text;"`
	LastComponentUpdate time.Time `json:"lastComponentUpdate"`
}

type AssetComponent struct {
	ID                 uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	AssetID            uuid.UUID `json:"assetId" gorm:"type:uuid;"`
	ComponentPurlOrCpe string    `json:"componentPurlOrCpe" gorm:"type:text;"`

	Component Component `json:"component" gorm:"foreignKey:ComponentPurlOrCpe;references:PurlOrCpe;constraint:OnDelete:CASCADE;"`
	Asset     Asset     `json:"asset" gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE;"`

	SemverStart string  `json:"semver_start" gorm:"type:semver;index;"` // might be nil, if the component was introduced in the latest version, which does not have a tag or name yet.
	SemverEnd   *string `json:"semver_end" gorm:"type:semver;index"`    // will be nil if the component is still used in latest
}

func (m Asset) TableName() string {
	return "assets"
}

func (m AssetComponent) TableName() string {
	return "asset_components"
}

func (m Asset) GetCurrentAssetComponents() []AssetComponent {
	assetComponents := make([]AssetComponent, 0)
	for _, assetComponent := range m.Components {
		if assetComponent.SemverEnd == nil {
			assetComponents = append(assetComponents, assetComponent)
		}
	}
	return assetComponents
}
