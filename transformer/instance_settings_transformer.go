package transformer

import (
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

func InstanceSettingsToDTO(settings shared.InstanceSettings, gitlabOAuthConfigs []dtos.GitlabOauth2Config) dtos.InstanceSettings {
	return dtos.InstanceSettings{
		SingleOrganizationMode:  settings.SingleOrganizationMode,
		BearerTokenAuthDisabled: settings.BearerTokenAuthDisabled,
		GitlabOAuth2Config:      gitlabOAuthConfigs,
	}
}
