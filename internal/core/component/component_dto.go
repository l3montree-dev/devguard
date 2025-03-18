package component

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type componentDTO struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`

	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Component     models.Component `json:"component" gorm:"foreignKey:ComponentPurl;references:Purl"`
	ComponentPurl *string          `json:"componentPurl" gorm:"column:component_purl;"` // will be nil, for direct dependencies
	AssetID       uuid.UUID        `json:"assetVersionId"`
	ScannerID     string           `json:"scannerId" gorm:"column:scanner_id"` // the id of the scanner
}

func toDTO(m models.ComponentDependency) componentDTO {
	return componentDTO{
		ID:            m.ID,
		Component:     m.Component,
		ComponentPurl: m.ComponentPurl,
		AssetID:       m.AssetID,
		ScannerID:     m.ScannerID,
	}
}
