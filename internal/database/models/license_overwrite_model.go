package models

import "github.com/google/uuid"

type LicenseOverwrite struct {
	License_id     string    `json:"licenseId" gorm:"primarykey;type:text"`
	OrganizationId uuid.UUID `json:"organizationId" gorm:"type:uuid;foreignKey:OrganizationID;references:ID;"`
	ComponentPurl  string    `json:"componentPurl" gorm:"type:text"`
	Justification  string    `json:"justification" gorm:"type:text"`
}

func (m LicenseOverwrite) TableName() string {
	return "license_overwrite"
}
