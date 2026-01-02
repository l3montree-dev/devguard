package dtos

type RelationshipType = string

const (
	RelationshipTypeAlias    RelationshipType = "alias"
	RelationshipTypeUpstream RelationshipType = "upstream"
	RelationshipTypeRelated  RelationshipType = "related"
)
