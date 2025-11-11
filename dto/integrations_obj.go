package dtos

type GitlabIntegrationDTO struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
}

type JiraIntegrationDTO struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
	UserEmail       string `json:"userEmail"`
}

type WebhookIntegrationDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
