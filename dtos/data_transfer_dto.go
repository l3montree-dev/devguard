package dtos

import "github.com/google/uuid"

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
	TargetOrgID     uuid.UUID  // org of an imported project or asset
	TargetProjectID *uuid.UUID // optional parent of an imported project, project of an imported asset
}
