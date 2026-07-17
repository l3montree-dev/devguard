// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

type ExternalReference struct {
	AssetID          uuid.UUID                  `json:"assetId" gorm:"primarykey;type:uuid;not null;index"`
	AssetVersionName string                     `json:"assetVersionName" gorm:"primarykey;type:text;not null;index"`
	URL              string                     `json:"url" gorm:"primarykey;type:text;not null"`
	Type             dtos.ExternalReferenceType `json:"type" gorm:"type:text;not null"` // "cyclonedx", "csaf", etc.
	Asset            Asset                      `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	AssetVersion     AssetVersion               `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
	Error            *string                    `gorm:"type:text"` // optional error message if the reference could not be processed
}

func (e ExternalReference) TableName() string {
	return "external_references"
}
