package models

import "github.com/google/uuid"

type ComponentOccurrence struct {
	ComponentDependencyID uuid.UUID `json:"componentDependencyId" gorm:"column:component_dependency_id"`
	DependencyPurl        *string   `json:"dependencyPurl" gorm:"column:dependency_purl"`
	OrganizationID        uuid.UUID `json:"organizationId" gorm:"column:organization_id"`
	OrganizationName      string    `json:"organizationName" gorm:"column:organization_name"`
	ProjectID             uuid.UUID `json:"projectId" gorm:"column:project_id"`
	ProjectName           string    `json:"projectName" gorm:"column:project_name"`
	ProjectSlug           string    `json:"projectSlug" gorm:"column:project_slug"`
	AssetID               uuid.UUID `json:"assetId" gorm:"column:asset_id"`
	AssetName             string    `json:"assetName" gorm:"column:asset_name"`
	AssetSlug             string    `json:"assetSlug" gorm:"column:asset_slug"`
	AssetVersionName      string    `json:"assetVersionName" gorm:"column:asset_version_name"`
	ComponentPurl         *string   `json:"componentPurl" gorm:"column:component_purl"`
	ComponentVersion      *string   `json:"componentVersion" gorm:"column:component_version"`
	ArtifactName          *string   `json:"artifactName" gorm:"column:artifact_name"`
	ArtifactAssetVersion  *string   `json:"artifactAssetVersion" gorm:"column:artifact_asset_version_name"`
}
