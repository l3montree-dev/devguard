package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

type Advisory struct {
	Vulnerability    `gorm:"-"`
	ID               uuid.UUID         `json:"id" gorm:"primaryKey;type:uuid;column:id;default:gen_random_uuid()"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	Title            string            `json:"title" gorm:"type:text;column:title"`
	Description      string            `json:"description" gorm:"type:text;column:description"`
	AffectedPackages []AffectedPackage `json:"affectedPackages" gorm:"many2many:advisories_affected_packages;foreignKey:ID;joinForeignKey:advisory_id;References:ID;joinReferences:affected_package_id;constraint:OnDelete:CASCADE"`
	Severity         string            `json:"severity" gorm:"type:text;column:severity"`
	VectorString     string            `json:"vectorString" gorm:"type:text;column:vector_string"`
	AssetID          uuid.UUID         `json:"assetID" gorm:"type:uuid;column:asset_id"`
	Visibility       string            `json:"visibility" gorm:"type:text;column:visibility;default:draft"`
	Events           []VulnEvent       `json:"events" gorm:"foreignKey:SecurityAdvisoryID;constraint:OnDelete:CASCADE;"`
}
type AffectedPackage struct {
	Model
	Ecosystem        string     `json:"ecosystem" gorm:"type:text;column:ecosystem"`
	PackageName      string     `json:"packageName" gorm:"type:text;column:package_name"`
	SemverIntroduced *string    `json:"semverStart" gorm:"type:text;index"`
	SemverFixed      *string    `json:"semverEnd" gorm:"type:text;index"`
	Advisory         []Advisory `json:"-" gorm:"many2many:advisories_affected_packages;constraint:OnDelete:CASCADE"`
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

func (m *Advisory) SetState(state dtos.VulnState) {
	switch state {
	case dtos.VulnStatePublished:
		m.Visibility = "public"
	case dtos.VulnStateWithdrawn:
		m.Visibility = "withdrawn"
	}
}

func (m *Advisory) GetState() dtos.VulnState {
	switch m.Visibility {
	case "public":
		return dtos.VulnStatePublished
	case "withdrawn":
		return dtos.VulnStateWithdrawn
	default:
		return dtos.VulnState(m.Visibility)
	}
}

func (m Advisory) GetEvents() []VulnEvent {
	return m.Events
}

func (m Advisory) GetArtifacts() []Artifact {
	return nil
}

func (m Advisory) AssetVersionIndependentHash() string {
	return ""
}

func (m Advisory) CalculateHash() uuid.UUID {
	return uuid.Nil
}
