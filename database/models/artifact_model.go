// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

type Artifact struct {
	CreatedAt time.Time `json:"createdAt"`

	ID             uuid.UUID    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ArtifactName   string       `json:"artifactName" gorm:"not null;"`
	AssetVersionID uuid.UUID    `json:"assetVersionId" gorm:"not null;type:uuid;"`
	AssetID        uuid.UUID    `json:"vulnAssetId" gorm:"not null;type:uuid;"`
	AssetVersion   AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionID;references:ID;constraint:OnDelete:CASCADE;"`

	DependencyVuln []DependencyVuln `json:"dependencyVulns" gorm:"many2many:artifact_dependency_vulns;constraint:OnDelete:CASCADE;"`
	LicenseRisks   []LicenseRisk    `json:"licenseRisks" gorm:"many2many:artifact_license_risks;constraint:OnDelete:CASCADE;"`
}

func (a Artifact) TableName() string {
	return "artifacts"
}
