package component

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type componentDTO struct {
	ID uuid.UUID `json:"id"`

	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Dependency     models.Component `json:"dependency"`
	DependencyPurl string           `json:"dependencyPurl"` // will be nil, for direct dependencies
	AssetID        uuid.UUID        `json:"assetVersionId"`
	ScannerIDs     string           `json:"scanner"` // the id of the scanner
}

func toDTO(m models.ComponentDependency) componentDTO {
	return componentDTO{
		ID:             m.ID,
		Dependency:     m.Dependency,
		DependencyPurl: m.DependencyPurl,
		AssetID:        m.AssetID,
		ScannerIDs:     m.ScannerIDs,
	}
}
