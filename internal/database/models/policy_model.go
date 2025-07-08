package models

import "github.com/google/uuid"

type Policy struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Rego          string    `json:"rego"`
	Title         string    `json:"title"`
	PredicateType string    `json:"predicateType"`
	Description   string    `json:"description"`

	OrganizationID *uuid.UUID `json:"organizationId"` // will be null for global policies
	Organization   *Org       `json:"organization" gorm:"foreignKey:OrganizationID;references:ID;constraint:OnDelete:CASCADE;"`

	OpaqueID string    `json:"opaqueId" gorm:"unique"` // only used by global policies maintained by the community and migrated by the system
	Projects []Project `json:"projects" gorm:"many2many:project_enabled_policies;"`
}

func (m Policy) TableName() string {
	return "policies"
}
