package models

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/database"
	"gorm.io/gorm"
)

type AttestationType string

type Attestation struct {
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	PredicateType    string         `json:"predicateType" gorm:"type:text;primaryKey"`
	AssetVersionName string         `json:"assetVersionName" gorm:"primaryKey"`
	AssetID          string         `json:"assetId" gorm:"primaryKey"`
	ArtifactName     string         `json:"artifactName" gorm:"primaryKey"`

	Artifact Artifact `json:"artifact" gorm:"foreignKey:ArtifactName,AssetID,AssetVersionName;constraint:OnDelete:CASCADE;"`

	Content database.JSONB `json:"content" gorm:"type:jsonb"`
}

func (m Attestation) TableName() string {
	return "attestations"
}
