package vuln

import "github.com/l3montree-dev/devguard/internal/database/models"

type ComponentOccurrenceDTO struct {
	ComponentDependencyID string  `json:"componentDependencyId"`
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
}

func convertComponentOccurrenceToDTO(m models.ComponentOccurrence) ComponentOccurrenceDTO {
	return ComponentOccurrenceDTO{
		ComponentDependencyID: m.ComponentDependencyID.String(),
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
	}
}
