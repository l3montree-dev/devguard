// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import "github.com/google/uuid"

type Artifact struct {
	ArtifactName     string        `json:"artifactName" gorm:"primaryKey;not null;"`
	AssetVersionName string        `json:"assetVersionName" gorm:"not null;"`
	AssetID          uuid.UUID     `json:"vulnAssetId" gorm:"not null;"`
	AssetVersion     *AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
}

func (a Artifact) TableName() string {
	return "artifacts"
}
