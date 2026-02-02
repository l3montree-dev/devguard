// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"github.com/google/uuid"
)

type ExternalReference struct {
	ID               uuid.UUID `json:"id" gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	AssetID          uuid.UUID `json:"assetId" gorm:"type:uuid;not null;index"`
	AssetVersionName string    `json:"assetVersionName" gorm:"type:text;not null;index"`
	URL              string    `json:"url" gorm:"type:text;not null"`
	Type             string    `json:"type" gorm:"type:text;not null"` // "vex", "sbom", "csaf", etc.
	// Relationships
	Asset        Asset        `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	AssetVersion AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
}

func (e ExternalReference) TableName() string {
	return "external_references"
}
