package models

type LicenseRisk struct {
	Vulnerability
	FinalLicenseDecision string `json:"finalLicenseDecision" gorm:"type:text"`
	ComponentPurl        string `json:"componentPurl" gorm:"type:text;primarykey"`
}

func (m LicenseRisk) TableName() string {
	return "license_risks"
}
