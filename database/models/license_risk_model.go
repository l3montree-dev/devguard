package models

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type LicenseRisk struct {
	Vulnerability

	Events []VulnEvent `gorm:"foreignKey:LicenseRiskID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`

	FinalLicenseDecision *string    `json:"finalLicenseDecision" gorm:"type:text"`
	ComponentPurl        string     `json:"componentPurl" gorm:"type:text;"` // only valid purls
	Component            Component  `json:"component" gorm:"foreignKey:ComponentPurl;references:ID;constraint:OnDelete:CASCADE;"`
	Artifacts            []Artifact `json:"artifacts" gorm:"many2many:artifact_license_risks;constraint:OnDelete:CASCADE"`
}

func (licenseRisk *LicenseRisk) SetFinalLicenseDecision(finalLicenseDecision string) {
	licenseRisk.FinalLicenseDecision = &finalLicenseDecision
}

func (licenseRisk *LicenseRisk) GetArtifacts() []Artifact {
	return licenseRisk.Artifacts
}

func (licenseRisk LicenseRisk) TableName() string {
	return "license_risks"
}

func (licenseRisk LicenseRisk) GetType() dtos.VulnType {
	return dtos.VulnTypeLicenseRisk
}

func (licenseRisk *LicenseRisk) CalculateHash() uuid.UUID {
	return utils.HashToUUID(fmt.Sprintf("%s/%s/%s", licenseRisk.ComponentPurl, licenseRisk.AssetVersionName, licenseRisk.AssetID))
}

func (licenseRisk *LicenseRisk) BeforeSave(tx *gorm.DB) (err error) {
	licenseRisk.ID = licenseRisk.CalculateHash()
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

func (licenseRisk LicenseRisk) AssetVersionIndependentHash() string {
	return utils.HashString(licenseRisk.ComponentPurl)
}

func (licenseRisk LicenseRisk) GetAssetVersionName() string {
	return licenseRisk.AssetVersionName
}

func (licenseRisk LicenseRisk) GetEvents() []VulnEvent {
	return licenseRisk.Events
}

func (licenseRisk LicenseRisk) Title() string {
	return fmt.Sprintf("License risk found in %s", licenseRisk.ComponentPurl)
}
