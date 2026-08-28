package dtos

type WebhookUpdateRequestDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url" validate:"required"`
	Secret      string `json:"secret"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
type WebhookCreateRequestDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url" validate:"required"`
	Secret      string `json:"secret"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
type WebhookTestRequestDTO struct {
	URL         string `json:"url" validate:"required"`
	Secret      string `json:"secret"`
	PayloadType string `json:"payloadType"`
}
