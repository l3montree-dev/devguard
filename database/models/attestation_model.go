package models

import (
	"time"

	"github.com/google/uuid"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
)

type AttestationType string

type Attestation struct {
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	PredicateType string    `json:"predicateType" gorm:"type:text;primaryKey"`
	ArtifactID    uuid.UUID `json:"artifactId" gorm:"primaryKey;type:uuid"`
	AssetID       uuid.UUID `json:"assetId" gorm:"type:uuid;not null;"`

	Artifact Artifact `json:"artifact" gorm:"foreignKey:ArtifactID;references:ID;constraint:OnDelete:CASCADE;"`

	// not stored in this table, filled by joining artifacts and asset_versions
	ArtifactName     string `json:"artifactName" gorm:"->;-:migration"`
	AssetVersionName string `json:"assetVersionName" gorm:"->;-:migration"`

	Content databasetypes.JSONB `json:"content" gorm:"type:jsonb"`
}

func (m Attestation) TableName() string {
	return "attestations"
}
