package dtos

type InstanceSettings struct {
	SingleOrganizationMode  bool                 `json:"singleOrganizationMode"`
	BearerTokenAuthDisabled bool                 `json:"bearerTokenAuthDisabled"`
	GitlabOAuth2Config      []GitlabOauth2Config `json:"gitlabOAuth2Config"`
}
