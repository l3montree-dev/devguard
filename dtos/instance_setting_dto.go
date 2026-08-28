package dtos

type InstanceSettingsDTO struct {
	SingleOrganizationMode  bool                    `json:"singleOrganizationMode"`
	BearerTokenAuthDisabled bool                    `json:"bearerTokenAuthDisabled"`
	GitlabOAuth2Config      []GitlabOauth2ConfigDTO `json:"gitlabOAuth2Config"`
}
