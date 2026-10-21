package dtos

type RelationshipType = string

const (
	RelationshipTypeAlias    RelationshipType = "alias"
	RelationshipTypeUpstream RelationshipType = "upstream"
	RelationshipTypeRelated  RelationshipType = "related"
	RelationshipTypeEUVD     RelationshipType = "euvd"     // flag relationships only imported through euvd explicitly
	RelationshipTypeAdvisory RelationshipType = "advisory" // flag relationships which stem from ingested security advisories
)

// CVERelationship is the API response shape.
// TargetCVE is the resolved CVE when the target exists in our database, nil otherwise.
type CVERelationship struct {
	SourceCVE        string           `json:"source_cve"`
	TargetCVEID      string           `json:"target_cve"`
	RelationshipType RelationshipType `json:"relationship_type"`
	TargetCVE        *CVE             `json:"target_cve_data,omitempty"`
}
