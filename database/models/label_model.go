package models

import (
	"time"

	"github.com/google/uuid"
)

type Label struct {
	ID              uuid.UUID  `json:"id" gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	OrganizationID  *uuid.UUID `json:"organization_id"`
	ProjectID       *uuid.UUID `json:"project_id"`
	AssetID         *uuid.UUID `json:"asset_id"`
	Label           string     `json:"label"`
	BackgroundColor string     `json:"background_color"`
	CreatedAt       time.Time  `json:"created_at"`
	Projects        []Project  `json:"projects" gorm:"many2many:projects_assets_artifacts_labels"`
	Assets          []Asset    `json:"assets" gorm:"many2many:projects_assets_artifacts_labels"`
	Artifacts       []Artifact `json:"artifacts" gorm:"many2many:projects_assets_artifacts_labels"`
}

func (l Label) TableName() string {
	return "labels"
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// reports whether the label is defined exactly on the given level.
func (l Label) IsDefinedAt(orgID uuid.UUID, projectID, assetID *uuid.UUID) bool {
	return l.OrganizationID != nil && *l.OrganizationID == orgID &&
		sameID(l.ProjectID, projectID) && sameID(l.AssetID, assetID)
}

// reports whether the label can be used on the given level:
func (l Label) IsVisibleFrom(orgID uuid.UUID, projectID, assetID *uuid.UUID) bool {
	if l.OrganizationID == nil || *l.OrganizationID != orgID {
		return false
	}
	if l.ProjectID != nil && !sameID(l.ProjectID, projectID) {
		return false
	}
	if l.AssetID != nil && !sameID(l.AssetID, assetID) {
		return false
	}
	return true
}
