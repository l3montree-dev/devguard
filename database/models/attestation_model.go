package models

import (
	"time"

	"github.com/google/uuid"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
)

type AttestationType string

type Attestation struct {
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	PredicateType    string    `json:"predicateType" gorm:"type:text;primaryKey"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey"`

	// Ensure foreign key field order matches Artifact primary key: ArtifactName, AssetVersionName, AssetID
	Artifact Artifact `json:"artifact" gorm:"foreignKey:ArtifactName,AssetVersionName,AssetID;constraint:OnDelete:CASCADE;"`

	Content databasetypes.JSONB `json:"content" gorm:"type:jsonb"`
}

func (m Attestation) TableName() string {
	return "attestations"
}
