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
