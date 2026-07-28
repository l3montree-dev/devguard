package models

import "github.com/l3montree-dev/devguard/dtos"

// CVERelationship stores source/target/type — TargetCVE is a plain string, not a DB FK constraint.
type CVERelationship struct {
	SourceCVE        string                `json:"source_cve" gorm:"type:text;primaryKey"` // an external CVE-ID (like DEBIAN-CVE-...)
	TargetCVE        string                `json:"target_cve" gorm:"type:text;primaryKey"` // the official CVE-XXXX-...  the external CVE-ID relates to
	RelationshipType dtos.RelationshipType `json:"relationship_type" gorm:"type:text;primaryKey"`
	// TargetCVEData is populated by GORM nested preload. It is nil when the target
	// CVE does not exist in this database — no DB-level FK constraint is added.
	TargetCVEData *CVE `json:"target_cve_data,omitempty" gorm:"foreignKey:TargetCVE;references:CVE"`
}

func (cve CVERelationship) TableName() string {
	return "cve_relationships"
}
