package models

import "github.com/google/uuid"

type Advisory struct {
	Model
	Title            string            `json:"title" gorm:"type:text;column:title"`
	Description      string            `json:"description" gorm:"type:text;column:description"`
	AffectedPackages []AffectedPackage `json:"affectedPackages" gorm:"many2many:advisories_affected_packages;foreignKey:ID;joinForeignKey:advisory_id;References:ID;joinReferences:affected_package_id;constraint:OnDelete:CASCADE"`
	Severity         string            `json:"severity" gorm:"type:text;column:severity"`
	VectorString     string            `json:"vectorstring" gorm:"type:text;column:vector_string"`
	AssetID          uuid.UUID         `json:"assetID" gorm:"type:uuid;column:asset_id"`
}
type AffectedPackage struct {
	Model
	Ecosystem        string     `json:"ecosystem" gorm:"type:text;column:ecosystem"`
	PackageName      string     `json:"packagename" gorm:"type:text;column:package_name"`
	SemverIntroduced *string    `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed      *string    `json:"semverEnd" gorm:"type:semver;index"`
	Advisory         []Advisory `json:"advisory" gorm:"many2many:advisories_affected_packages;constraint:OnDelete:CASCADE"`
}

func (m Advisory) TableName() string {
	return "advisories"
}

func (m AffectedPackage) TableName() string {
	return "affected_packages"
}
