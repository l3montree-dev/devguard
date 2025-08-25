package models

import (
	"fmt"

	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type LicenseRisk struct {
	Vulnerability
	FinalLicenseDecision *string    `json:"finalLicenseDecision" gorm:"type:text"`
	ComponentPurl        string     `json:"componentPurl" gorm:"type:text;primarykey"`
	Component            Component  `json:"component" gorm:"foreignKey:ComponentPurl;references:Purl;constraint:OnDelete:CASCADE;"`
	Artifacts            []Artifact `json:"artifacts" gorm:"many2many:artifact_license_risks;constraint:OnDelete:CASCADE"`
}

func (licenseRisk *LicenseRisk) SetFinalLicenseDecision(finalLicenseDecision string) {
	licenseRisk.FinalLicenseDecision = &finalLicenseDecision
}

func (licenseRisk LicenseRisk) TableName() string {
	return "license_risks"
}

func (licenseRisk LicenseRisk) GetType() VulnType {
	return VulnTypeLicenseRisk
}

func (licenseRisk *LicenseRisk) CalculateHash() string {
	// we should only use static and unique information for the hash ( maybe we need to add scanner IDs, see pull request)
	hash := utils.HashString(fmt.Sprintf("%s/%s/%s", licenseRisk.ComponentPurl, licenseRisk.AssetVersionName, licenseRisk.AssetID))
	return hash
}

func (licenseRisk *LicenseRisk) BeforeSave(tx *gorm.DB) (err error) {
	hash := licenseRisk.CalculateHash()
	licenseRisk.ID = hash
	return nil
}

func (licenseRisk *LicenseRisk) GetArtifactNames() string {
	artifactNames := ""
	for _, artifact := range licenseRisk.Artifacts {
		if artifactNames != "" {
			artifactNames += ", "
		}
		artifactNames += artifact.ArtifactName
	}
	return artifactNames
}
