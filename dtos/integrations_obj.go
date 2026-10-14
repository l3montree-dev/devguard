package dtos

type GitlabIntegration struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
}

type JiraIntegration struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
	UserEmail       string `json:"userEmail"`
}

type WebhookIntegration struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
