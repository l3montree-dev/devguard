package models

import (
	"github.com/google/uuid"
)

type Project struct {
	Model
	Name           string    `json:"name" gorm:"type:text"`
	Assets         []Asset   `json:"assets" gorm:"foreignKey:ProjectID;constraint:OnDelete:CASCADE;"`
	OrganizationID uuid.UUID `json:"organizationId" gorm:"uniqueIndex:idx_project_org_slug;not null;type:uuid"`
	Slug           string    `json:"slug" gorm:"type:text;uniqueIndex:idx_project_org_slug;not null"`
	Description    string    `json:"description" gorm:"type:text"`

	IsPublic bool `json:"isPublic" gorm:"default:false;"`

	KubernetesClusterID *string `json:"kubernetesClusterId" gorm:"type:text;default:null;"` // nullable - if set, the project is management by the devguard operator. Name will be the namespace, assets will be images running in that namespace
}

func (m Project) TableName() string {
	return "projects"
}
