package dtos

type AffectedEntities struct {
	Orgs     []string `json:"orgs"`
	Projects []string `json:"projects"`
	Assets   []string `json:"assets"`
}

type DataTransferExportOptions struct {
	AffectedEntities AffectedEntities
}
