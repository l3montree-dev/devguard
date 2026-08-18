package models

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"gorm.io/gorm"
)

type Advisory struct {
	Vulnerability
	Title            string            `json:"title" gorm:"type:text;column:title"`
	Description      string            `json:"description" gorm:"type:text;column:description"`
	AffectedPackages []AffectedPackage `json:"affectedPackages" gorm:"many2many:advisories_affected_packages;foreignKey:ID;joinForeignKey:advisory_id;References:ID;joinReferences:affected_package_id;constraint:OnDelete:CASCADE"`
	Severity         string            `json:"severity" gorm:"type:text;column:severity"`
	VectorString     string            `json:"vectorString" gorm:"type:text;column:vector_string"`
	Events           []VulnEvent       `json:"events" gorm:"foreignKey:SecurityAdvisoryID;constraint:OnDelete:CASCADE;"`
}
type AffectedPackage struct {
	Model
	Ecosystem         string     `json:"ecosystem" gorm:"type:text;column:ecosystem"`
	PackageName       string     `json:"packageName" gorm:"type:text;column:package_name"`
	VersionIntroduced *string    `json:"versionStart" gorm:"type:text;index"`
	VersionFixed      *string    `json:"versionEnd" gorm:"type:text;index"`
	Advisory          []Advisory `json:"-" gorm:"many2many:advisories_affected_packages;constraint:OnDelete:CASCADE"`
}

func (m Advisory) TableName() string {
	return "advisories"
}

func (m AffectedPackage) TableName() string {
	return "affected_packages"
}

func (m Advisory) GetType() dtos.VulnType {
	return dtos.VulnTypeSecurityAdvisory
}

func (m *Advisory) BeforeSave(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

func (m Advisory) GetEvents() []VulnEvent {
	return m.Events
}

func (m Advisory) GetArtifacts() []Artifact {
	return nil
}

func (m Advisory) CalculateAssetVersionIndependentHash() string {
	return ""
}

func (m Advisory) CalculateHash() uuid.UUID {
	return uuid.Nil
}
