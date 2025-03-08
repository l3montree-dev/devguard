package common

type GitlabIntegrationDTO struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	Url             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
}
