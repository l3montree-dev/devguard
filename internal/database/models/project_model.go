package models

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
)

type ProjectType string

const (
	ProjectTypeDefault             ProjectType = "default"
	ProjectTypeKubernetesNamespace ProjectType = "kubernetesNamespace"
	ProjectTypeKubernetesCluster   ProjectType = "kubernetesCluster"
)

type Project struct {
	Model
	Name           string    `json:"name" gorm:"type:text"`
	Assets         []Asset   `json:"assets" gorm:"foreignKey:ProjectID;"`
	OrganizationID uuid.UUID `json:"organizationId" gorm:"uniqueIndex:idx_project_org_slug;not null;type:uuid"`
	Organization   Org       `json:"organization" gorm:"foreignKey:OrganizationID;references:ID;constraint:OnDelete:CASCADE;"`
	Slug           string    `json:"slug" gorm:"type:text;uniqueIndex:idx_project_org_slug;not null"`
	Description    string    `json:"description" gorm:"type:text"`

	IsPublic bool `json:"isPublic" gorm:"default:false;"`

	Children []Project  `json:"-" gorm:"foreignKey:ParentID;constraint:OnDelete:CASCADE;"` // allowing nested projects
	ParentID *uuid.UUID `json:"parentId" gorm:"type:uuid;"`
	Parent   *Project   `json:"parent" gorm:"foreignKey:ParentID;constraint:OnDelete:CASCADE;"`

	Type ProjectType `json:"type" gorm:"type:text;default:'default';"`

	RepositoryID   *string `json:"repositoryId" gorm:"type:text;"` // the id will be prefixed with the provider name, e.g. github:<github app installation id>:123456
	RepositoryName *string `json:"repositoryName" gorm:"type:text;"`

	ConfigFiles database.JSONB `json:"configFiles" gorm:"type:jsonb"`

	EnabledPolicies []Policy `json:"enabledPolicies" gorm:"many2many:project_enabled_policies;constraint:OnDelete:CASCADE;"`

	ExternalEntityID         *string `json:"externalEntityId" gorm:"uniqueIndex:unique_external_entity;"`
	ExternalEntityProviderID *string `json:"externalEntityProviderId" gorm:"uniqueIndex:unique_external_entity;"`

	Webhooks []WebhookIntegration `json:"webhooks" gorm:"foreignKey:ProjectID;"`
}

func (m Project) TableName() string {
	return "projects"
}

func (m Project) IsExternalEntity() bool {
	return m.ExternalEntityProviderID != nil && *m.ExternalEntityProviderID != ""
}

func (m *Project) Same(other *Project) bool {
	if m.ExternalEntityID == nil || m.ExternalEntityProviderID == nil {
		return m.ID != uuid.Nil && m.ID == other.ID
	}

	return *m.ExternalEntityID == *other.ExternalEntityID &&
		*m.ExternalEntityProviderID == *other.ExternalEntityProviderID
}

func (m *Project) GetSlug() string {
	return m.Slug
}

func (m *Project) SetSlug(slug string) {
	m.Slug = slug
}
