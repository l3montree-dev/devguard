package dtos

type GitlabOauth2Config struct {
	ProviderID    string `json:"providerID"`
	GitlabBaseURL string `json:"gitlabBaseURL"`
}
