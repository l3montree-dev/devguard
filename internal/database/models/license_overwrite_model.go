package models

import "github.com/google/uuid"

type LicenseOverwrite struct {
	LicenseID      string    `json:"licenseId" gorm:"type:text"`
	OrganizationID uuid.UUID `json:"organizationId" gorm:"type:uuid;foreignKey:OrganizationID;references:ID;OnDelete:CASCADE;primarykey"`
	ComponentPurl  string    `json:"componentPurl" gorm:"type:text;primarykey"`
	Justification  string    `json:"justification" gorm:"type:text"`
}

func (m LicenseOverwrite) TableName() string {
	return "license_overwrite"
}
