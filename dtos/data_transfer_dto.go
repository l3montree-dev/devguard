package dtos

type affectedEntities struct {
	Orgs, Projects, Assets []string
}

type DataTransferExportOptions struct {
	AffectedEntities affectedEntities
}
