package dtos

import (
	"time"

	"github.com/google/uuid"
)

type DataTransferEntityType string

const (
	DataTransferEntityOrg     DataTransferEntityType = "org"
	DataTransferEntityProject DataTransferEntityType = "project"
	DataTransferEntityAsset   DataTransferEntityType = "asset"
)

// the exported entity is exported as a whole, including everything below it
type DataTransferExportOptions struct {
	EntityType DataTransferEntityType
	EntityID   uuid.UUID
}

type DataTransferImportOptions struct {
	EntityType      DataTransferEntityType // scope of the data transfer
	OwnerID         string                 // gets the highest role on all imported entities
	TargetOrgID     uuid.UUID              // target org the project gets attached to
	TargetProjectID *uuid.UUID             // target project a project or asset gets attached to
}

type DataTransferMetadata struct {
	ExportVersion         int                    `json:"export_version"`
	DatabaseSchemaVersion string                 `json:"database_schema_version"`
	ExportTimestamp       time.Time              `json:"export_timestamp"`
	EntityType            DataTransferEntityType `json:"entity_type"`
	EntityID              uuid.UUID              `json:"entity_id"`
}
