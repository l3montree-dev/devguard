// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"github.com/google/uuid"
)

type ExternalReferenceType string

const (
	ExternalReferenceTypeCycloneDxVEX ExternalReferenceType = "cyclonedxvex"
	ExternalReferenceTypeCSAF         ExternalReferenceType = "csaf"
)

type ExternalReference struct {
	ID               uuid.UUID             `json:"id" gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	AssetID          uuid.UUID             `json:"assetId" gorm:"type:uuid;not null;index"`
	AssetVersionName string                `json:"assetVersionName" gorm:"type:text;not null;index"`
	URL              string                `json:"url" gorm:"type:text;not null"`
	Type             ExternalReferenceType `json:"type" gorm:"type:text;not null"`    // "cyclonedx", "csaf", etc.
	CSAFPackageScope string                `json:"csafPackageScope" gorm:"type:text"` // "all", "known", "unknown", only relevant for csaf references
	// Relationships
	Asset        Asset        `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	AssetVersion AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
}

func (e ExternalReference) TableName() string {
	return "external_references"
}
