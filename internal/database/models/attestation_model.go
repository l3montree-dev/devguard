package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
	"gorm.io/gorm"
)

type AttestationType string

type Attestation struct {
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	AttestationName string `json:"attestationName" gorm:"type:text;primaryKey"`

	AssetVersionName string       `json:"assetVersionName" gorm:"not null;"`
	AssetID          uuid.UUID    `json:"flawAssetId" gorm:"not null;"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	Content database.JSONB `json:"content" gorm:"type:jsonb"`
}

func (m Attestation) TableName() string {
	return "attestations"
}
