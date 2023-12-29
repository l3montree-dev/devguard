package org

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/project"
)

type Model struct {
	core.Model
	Name                   string          `json:"name" gorm:"type:varchar(255)"`
	ContactPhoneNumber     *string         `json:"contactPhoneNumber" gorm:"type:varchar(255)"`
	NumberOfEmployees      *int            `json:"numberOfEmployees"`
	Country                *string         `json:"country" gorm:"type:varchar(255)"`
	Industry               *string         `json:"industry" gorm:"type:varchar(255)"`
	CriticalInfrastructure bool            `json:"criticalInfrastructure"`
	ISO27001               bool            `json:"iso27001"`
	NIST                   bool            `json:"nist"`
	Grundschutz            bool            `json:"grundschutz"`
	Projects               []project.Model `json:"projects" gorm:"foreignKey:OrganizationID;constraint:OnDelete:CASCADE;"`
	Slug                   string          `json:"slug" gorm:"type:varchar(255);unique;not null;index"`
	Description            string          `json:"description" gorm:"type:text"`
}

func (m Model) TableName() string {
	return "organizations"
}
