package asset

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
)

type AssetType string

const (
	AssetTypeApplication    AssetType = "application"
	AssetTypeInfrastructure AssetType = "infrastructure"
)

type Model struct {
	core.Model
	Name string `json:"name" gorm:"type:varchar(255)"`
	Slug string `json:"slug" gorm:"type:varchar(255);uniqueIndex:idx_app_project_slug;not null;"`

	ProjectID   uuid.UUID    `json:"projectId" gorm:"uniqueIndex:idx_app_project_slug;not null;"`
	Description string       `json:"description" gorm:"type:text"`
	Flaws       []flaw.Model `json:"flaws" gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE;"`

	Type AssetType `json:"type" gorm:"type:varchar(255);not null;"`
}

func (m Model) TableName() string {
	return "assets"
}
