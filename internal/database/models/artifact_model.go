// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package models

import "github.com/google/uuid"

type Artifact struct {
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;not null;"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;not null;type:text;"`
	AssetID          uuid.UUID `json:"vulnAssetId" gorm:"primaryKey;not null;type:uuid;"`

	AssetVersion AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	DependencyVuln        []DependencyVuln      `json:"dependencyVulns" gorm:"many2many:artifact_dependency_vulns;"`
	ComponentDependencies []ComponentDependency `json:"componentDependencies" gorm:"many2many:artifact_component_dependencies;"`
	LicenseRisks          []LicenseRisk         `json:"licenseRisks" gorm:"many2many:artifact_license_risks;"`
}

func (a Artifact) TableName() string {
	return "artifacts"
}
