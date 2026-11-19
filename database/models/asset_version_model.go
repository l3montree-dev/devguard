package models

import (
	"time"

	"github.com/google/uuid"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
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
	ID        uuid.UUID `json:"id" gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Name    string    `json:"name" gorm:"type:text;not null;"`
	AssetID uuid.UUID `json:"assetId" gorm:"not null;type:uuid;"`
	Asset   Asset     `json:"asset" gorm:"foreignKey:AssetID;references:ID; constraint:OnDelete:CASCADE;"`

	DefaultBranch   bool             `json:"defaultBranch" gorm:"default:false;"`
	Slug            string           `json:"slug" gorm:"type:text;not null;type:text;"`
	DependencyVulns []DependencyVuln `json:"dependencyVulns" gorm:"foreignKey:AssetVersionID;references:ID;constraint:OnDelete:CASCADE;"`
	Artifacts       []Artifact       `json:"artifacts" gorm:"foreignKey:AssetVersionID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Type            AssetVersionType `json:"type" gorm:"type:text;not null;"`
	SupplyChains    []SupplyChain    `json:"supplyChains" gorm:"foreignKey:AssetVersionID;references:ID;constraint:OnDelete:CASCADE;"`

	SigningPubKey *string             `json:"signingPubKey" gorm:"type:text;"`
	Metadata      databasetypes.JSONB `json:"metadata" gorm:"type:jsonb"`
	// only set by scans uploaded by a client - background rescans of upstream SBOMs do not count
	// includes both sbom and sarif imports
	LastUploadAt *time.Time `json:"lastUploadAt"`
}

func (m AssetVersion) TableName() string {
	return "asset_versions"
}

func (m AssetVersion) ToCELMap() map[string]any {
	res := map[string]any{
		"name":          m.Name,
		"slug":          m.Slug,
		"type":          string(m.Type),
		"defaultBranch": m.DefaultBranch,
		"createdAt":     TimeToCEL(m.CreatedAt),
		"updatedAt":     TimeToCEL(m.UpdatedAt),
	}
	// absent instead of null, so policies can guard with has(ref.lastUploadAt)
	if m.LastUploadAt != nil {
		res["lastUploadAt"] = TimeToCEL(*m.LastUploadAt)
	}
	return res
}
