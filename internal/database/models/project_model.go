package models

import (
	"time"

	"github.com/google/uuid"
)

type ProjectType string

const (
	ProjectTypeDefault             ProjectType = "default"
	ProjectTypeKubernetesNamespace ProjectType = "kubernetesNamespace"
)

type Project struct {
	Model
	Name           string    `json:"name" gorm:"type:text"`
	Assets         []Asset   `json:"assets" gorm:"foreignKey:ProjectID;constraint:OnDelete:CASCADE;"`
	OrganizationID uuid.UUID `json:"organizationId" gorm:"uniqueIndex:idx_project_org_slug;not null;type:uuid"`
	Slug           string    `json:"slug" gorm:"type:text;uniqueIndex:idx_project_org_slug;not null"`
	Description    string    `json:"description" gorm:"type:text"`

	IsPublic bool `json:"isPublic" gorm:"default:false;"`

	Children []Project  `json:"-" gorm:"foreignKey:ParentID;constraint:OnDelete:CASCADE;"` // allowing nested projects
	ParentID *uuid.UUID `json:"parentId" gorm:"type:uuid;"`
	Parent   *Project   `json:"parent" gorm:"foreignKey:ParentID;constraint:OnDelete:CASCADE;"`

	Type ProjectType `json:"type" gorm:"type:text;default:'default';"`

	Archived *time.Time `json:"archived" gorm:"default:null;"`
}

func (m Project) TableName() string {
	return "projects"
}
