package dtos

type RelationshipType = string

const (
	RelationshipTypeAlias    RelationshipType = "alias"
	RelationshipTypeUpstream RelationshipType = "upstream"
	RelationshipTypeRelated  RelationshipType = "related"
	RelationshipTypeEUVD     RelationshipType = "euvd"     // flag relationships only imported through euvd explicitly
	RelationshipTypeAdvisory RelationshipType = "advisory" // flag relationships which stem from ingested security advisories
)

// CVERelationshipDTO is the API response shape.
// TargetCVE is the resolved CVEDTO when the target exists in our database, nil otherwise.
type CVERelationshipDTO struct {
	SourceCVE        string           `json:"source_cve"`
	TargetCVEID      string           `json:"target_cve"`
	RelationshipType RelationshipType `json:"relationship_type"`
	TargetCVE        *CVEDTO          `json:"target_cve_data,omitempty"`
}
