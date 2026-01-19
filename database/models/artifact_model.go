// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

type Artifact struct {
	CreatedAt time.Time `json:"createdAt"`

	ArtifactName      string       `json:"artifactName" gorm:"primaryKey;not null;"`
	AssetVersionName  string       `json:"assetVersionName" gorm:"primaryKey;not null;type:text;"`
	AssetID           uuid.UUID    `json:"vulnAssetId" gorm:"primaryKey;not null;type:uuid;"`
	LastHistoryUpdate *time.Time   `json:"lastHistoryUpdate,omitempty"`
	AssetVersion      AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	DependencyVuln []DependencyVuln      `json:"dependencyVulns" gorm:"many2many:artifact_dependency_vulns;constraint:OnDelete:CASCADE;"`
	LicenseRisks   []LicenseRisk         `json:"licenseRisks" gorm:"many2many:artifact_license_risks;constraint:OnDelete:CASCADE;"`
	RiskHistories  []ArtifactRiskHistory `json:"riskHistories" gorm:"foreignKey:ArtifactName,AssetVersionName,AssetID;references:ArtifactName,AssetVersionName,AssetID;constraint:OnDelete:CASCADE;"`
}

func (a Artifact) TableName() string {
	return "artifacts"
}
