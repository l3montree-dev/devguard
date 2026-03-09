package accesscontrol

import (
	"github.com/l3montree-dev/devguard/utils"
	"github.com/ory/client-go"
)

func GetOryAPIClient(url string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: url},
	}
	cfg.HTTPClient = &utils.EgressClient

	ory := client.NewAPIClient(cfg)
	return ory
}
