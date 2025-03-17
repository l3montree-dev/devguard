package models

import (
	"time"

	"gorm.io/gorm"
)

type AttestationType string

type Attestation struct {
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	AttestationName string       `json:"attestationName" gorm:"type:text"`
	AssetVersionID  string       `json:"assetVersionID" gorm:"primarykey;not null;type:text"`
	AssetVersion    AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionID;references:Name"`

	//AttestationJSON jsonb `json:"attestationJSON"`
}

func (m Attestation) TableName() string {
	return "attestations"
}
