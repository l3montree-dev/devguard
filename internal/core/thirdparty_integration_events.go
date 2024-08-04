package core

type FlawDetectedEvent struct {
	AssetID      string  `json:"assetId"`
	RepositoryID *string `json:"repositoryId"`
}

type ManualMitigateEvent struct {
	Ctx Context
}
