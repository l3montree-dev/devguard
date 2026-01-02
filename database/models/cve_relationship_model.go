package models

import "github.com/l3montree-dev/devguard/dtos"

// this model is used to save information about the relationship between different CVEs, this data originates from the OSV import
// where every OSV entry has a set of aliases, related and upstream vulnerabilities
type CVERelationShip struct {
	SourceCVE        string                `json:"source_cve" gorm:"type:text;primaryKey"`
	TargetCVE        string                `json:"target_cve" gorm:"type:text;primaryKey"`
	RelationshipType dtos.RelationshipType `json:"relationship_type" gorm:"type:text;primaryKey"`
}

func (cve CVERelationShip) TableName() string {
	return "cve_relationships"
}
