package models

import (
	"time"

	"github.com/google/uuid"
)

type Label struct {
	ID              uuid.UUID  `json:"id" gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	OrganizationID  uuid.UUID  `json:"organizationID"`
	ProjectID       *uuid.UUID `json:"projectID"`
	AssetID         *uuid.UUID `json:"assetID"`
	Label           string     `json:"label"`
	Description     string     `json:"description"`
	BackgroundColor string     `json:"backgroundColor"`
	CreatedAt       time.Time  `json:"createdAt"`
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
	return l.OrganizationID == orgID &&
		sameID(l.ProjectID, projectID) && sameID(l.AssetID, assetID)
}
