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

// org archives are imported as a new org, project and asset archives get attached to an existing entity
type DataTransferImportOptions struct {
	OwnerID         string     // gets the highest role on the imported entity
	TargetOrgID     uuid.UUID  // org of an imported root project, resolved from the target project otherwise
	TargetProjectID *uuid.UUID // parent of an imported sub project, project of an imported asset
}

type DataTransferMetadata struct {
	ExportVersion         int                    `json:"export_version"`
	DatabaseSchemaVersion string                 `json:"database_schema_version"`
	ExportTimestamp       time.Time              `json:"export_timestamp"`
	EntityType            DataTransferEntityType `json:"entity_type"`
	EntityID              uuid.UUID              `json:"entity_id"`
}
