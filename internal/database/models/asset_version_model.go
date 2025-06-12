package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
	"gorm.io/gorm"
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
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name    string    `json:"name" gorm:"primarykey;type:text;not null;"`
	AssetID uuid.UUID `json:"assetId" gorm:"primarykey;not null;type:uuid;"`
	Asset   Asset     `json:"asset" gorm:"foreignKey:AssetID;references:ID; constraint:OnDelete:CASCADE;"`

	Attestations    []Attestation         `json:"attestations"  gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
	DefaultBranch   bool                  `json:"defaultBranch" gorm:"default:false;"`
	Slug            string                `json:"slug" gorm:"type:text;not null;type:text;"`
	DependencyVulns []DependencyVuln      `json:"dependencyVulns" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
	Type            AssetVersionType      `json:"type" gorm:"type:text;not null;"`
	Components      []ComponentDependency `json:"components" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;"`
	SupplyChains    []SupplyChain         `json:"supplyChains" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;"`

	LastHistoryUpdate *time.Time
	SigningPubKey     *string `json:"signingPubKey" gorm:"type:text;"`

	Metadata database.JSONB `json:"metadata" gorm:"type:jsonb"`
}

func (m AssetVersion) TableName() string {
	return "asset_versions"
}
