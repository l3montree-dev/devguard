package models

import (
	"time"

	"github.com/google/uuid"
)

type SupplyChain struct {
	SupplyChainID           string    `json:"supplyChainId" gorm:"column:supply_chain_id;primaryKey"`
	Verified                bool      `json:"verified" gorm:"column:verified"`
	SupplyChainOutputDigest string    `json:"supplyChainOutputDigest" gorm:"column:supply_chain_output_digest"`
	CreatedAt               time.Time `json:"createdAt" gorm:"column:created_at"`
	UpdatedAt               time.Time `json:"updatedAt" gorm:"column:updated_at"`

	AssetVersion   AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionID;references:AssetVersionID"`
	AssetVersionID uuid.UUID    `json:"assetVersionId" gorm:"column:asset_version_id;not null"`
}

func (SupplyChain) TableName() string {
	return "supply_chain"
}
