package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
)

type AssetVersionType string

const (
	AssetVersionBranch AssetVersionType = "branch"
	AssetVersionTag    AssetVersionType = "tag"
)

type ScannerInformation struct {
	LastScan *time.Time `json:"lastScan,omitempty"`
}

type AssetVersion struct {
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Name    string    `json:"name" gorm:"primarykey;type:text;not null;"`
	AssetID uuid.UUID `json:"assetId" gorm:"primarykey;not null;type:uuid;"`
	Asset   Asset     `json:"asset" gorm:"foreignKey:AssetID;references:ID; constraint:OnDelete:CASCADE;"`

	DefaultBranch   bool                  `json:"defaultBranch" gorm:"default:false;"`
	Slug            string                `json:"slug" gorm:"type:text;not null;type:text;"`
	DependencyVulns []DependencyVuln      `json:"dependencyVulns" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
	Artifacts       []Artifact            `json:"artifacts" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Type            AssetVersionType      `json:"type" gorm:"type:text;not null;"`
	Components      []ComponentDependency `json:"components" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
	SupplyChains    []SupplyChain         `json:"supplyChains" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	SigningPubKey  *string        `json:"signingPubKey" gorm:"type:text;"`
	Metadata       database.JSONB `json:"metadata" gorm:"type:jsonb"`
	LastAccessedAt time.Time      `json:"lastAccessedAt,omitempty" gorm:"default:NOW();"`
}

func (m AssetVersion) TableName() string {
	return "asset_versions"
}
