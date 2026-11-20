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
