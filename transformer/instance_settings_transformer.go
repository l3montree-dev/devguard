package transformer

import (
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

func InstanceSettingsToDTO(settings shared.InstanceSettings, gitlabOAuthConfigs []dtos.GitlabOauth2ConfigDTO) dtos.InstanceSettingsDTO {
	return dtos.InstanceSettingsDTO{
		SingleOrganizationMode:  settings.SingleOrganizationMode,
		BearerTokenAuthDisabled: settings.BearerTokenAuthDisabled,
		GitlabOAuth2Config:      gitlabOAuthConfigs,
	}
}
