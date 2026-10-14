package dtos

type WebhookUpdateRequest struct {
	ID          string `json:"id" validate:"max=256"`
	Name        string `json:"name" validate:"max=256"`
	Description string `json:"description" validate:"max=4000"`
	URL         string `json:"url" validate:"required,max=2048"`
	Secret      string `json:"secret" validate:"max=1024"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
type WebhookCreateRequest struct {
	Name        string `json:"name" validate:"max=256"`
	Description string `json:"description" validate:"max=4000"`
	URL         string `json:"url" validate:"required,max=2048"`
	Secret      string `json:"secret" validate:"max=1024"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
type WebhookTestRequest struct {
	URL         string `json:"url" validate:"required,max=2048"`
	Secret      string `json:"secret" validate:"max=1024"`
	PayloadType string `json:"payloadType" validate:"max=256"`
}
