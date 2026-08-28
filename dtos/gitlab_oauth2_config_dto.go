package dtos

type GitlabOauth2ConfigDTO struct {
	ProviderID    string `json:"providerID"`
	GitlabBaseURL string `json:"gitlabBaseURL"`
}
