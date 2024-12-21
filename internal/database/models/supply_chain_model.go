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

	Asset   Asset     `json:"asset" gorm:"foreignKey:AssetID"`
	AssetID uuid.UUID `json:"assetId" gorm:"column:asset_id"`
}

func (SupplyChain) TableName() string {
	return "supply_chain"
}
