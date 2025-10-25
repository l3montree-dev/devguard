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

	UpstreamURLs          []ArtifactUpstreamURL `json:"upstreamUrls" gorm:"foreignKey:ArtifactArtifactName,ArtifactAssetVersionName,ArtifactAssetID;references:ArtifactName,AssetVersionName,AssetID;"`
	DependencyVuln        []DependencyVuln      `json:"dependencyVulns" gorm:"many2many:artifact_dependency_vulns;constraint:OnDelete:CASCADE;"`
	ComponentDependencies []ComponentDependency `json:"componentDependencies" gorm:"many2many:artifact_component_dependencies;constraint:OnDelete:CASCADE;"`
	LicenseRisks          []LicenseRisk         `json:"licenseRisks" gorm:"many2many:artifact_license_risks;constraint:OnDelete:CASCADE;"`
	RiskHistories         []ArtifactRiskHistory `json:"riskHistories" gorm:"foreignKey:ArtifactName,AssetVersionName,AssetID;references:ArtifactName,AssetVersionName,AssetID;constraint:OnDelete:CASCADE;"`
}

type ArtifactUpstreamURL struct {
	ArtifactArtifactName     string    `json:"artifactName" gorm:"column:artifact_artifact_name;not null;type:text;"`
	ArtifactAssetVersionName string    `json:"assetVersionName" gorm:"column:artifact_asset_version_name;not null;type:text;"`
	ArtifactAssetID          uuid.UUID `json:"vulnAssetId" gorm:"column:artifact_asset_id;not null;type:uuid;"`
	UpstreamURL              string    `json:"upstreamUrl" gorm:"column:upstream_url;not null;type:text;"`
}

func (a Artifact) TableName() string {
	return "artifacts"
}

func (a ArtifactUpstreamURL) TableName() string {
	return "artifact_upstream_urls"
}
