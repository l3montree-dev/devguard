package dtos

type AffectedEntities struct {
	Orgs, Projects, Assets []string
}

type DataTransferExportOptions struct {
	AffectedEntities AffectedEntities
}
