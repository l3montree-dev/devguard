package component

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type componentDTO struct {
	ID            uuid.UUID        `json:"id"`
	Component     models.Component `json:"component"`
	ComponentPurl string           `json:"componentPurl"`

	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Dependency     models.Component  `json:"dependency"`
	DependencyPurl string            `json:"dependencyPurl"` // will be nil, for direct dependencies
	Artifacts      []models.Artifact `json:"artifacts"`
}
type ComponentOccurrenceDTO struct {
	ComponentDependencyID string  `json:"componentDependencyId"`
	DependencyPurl        *string `json:"dependencyPurl"`
	OrganizationID        string  `json:"organizationId"`
	OrganizationName      string  `json:"organizationName"`
	ProjectID             string  `json:"projectId"`
	ProjectName           string  `json:"projectName"`
	ProjectSlug           string  `json:"projectSlug"`
	AssetID               string  `json:"assetId"`
	AssetName             string  `json:"assetName"`
	AssetSlug             string  `json:"assetSlug"`
	AssetVersionName      string  `json:"assetVersionName"`
	ComponentPurl         *string `json:"componentPurl"`
	ComponentVersion      *string `json:"componentVersion"`
	ArtifactName          *string `json:"artifactName"`
	ArtifactAssetVersion  *string `json:"artifactAssetVersion"`
}

func toDTO(m models.ComponentDependency) componentDTO {
	return componentDTO{
		ID:             m.ID,
		Component:      m.Component,
		ComponentPurl:  utils.SafeDereference(m.ComponentPurl),
		Dependency:     m.Dependency,
		DependencyPurl: m.DependencyPurl,
		Artifacts:      m.Artifacts,
	}
}

func convertComponentOccurrenceToDTO(m models.ComponentOccurrence) ComponentOccurrenceDTO {
	return ComponentOccurrenceDTO{
		ComponentDependencyID: m.ComponentDependencyID.String(),
		DependencyPurl:        m.DependencyPurl,
		OrganizationID:        m.OrganizationID.String(),
		OrganizationName:      m.OrganizationName,
		ProjectID:             m.ProjectID.String(),
		ProjectName:           m.ProjectName,
		ProjectSlug:           m.ProjectSlug,
		AssetID:               m.AssetID.String(),
		AssetName:             m.AssetName,
		AssetSlug:             m.AssetSlug,
		AssetVersionName:      m.AssetVersionName,
		ComponentPurl:         m.ComponentPurl,
		ComponentVersion:      m.ComponentVersion,
		ArtifactName:          m.ArtifactName,
		ArtifactAssetVersion:  m.ArtifactAssetVersion,
	}
}
