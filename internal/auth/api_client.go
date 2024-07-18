package auth

import (
	"context"

	"github.com/ory/client-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func GetOryApiClient(url string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: url},
	}

	ory := client.NewAPIClient(cfg)
	return ory
}

// GetOryApiAdminClient creates a client for the Ory Admin API with OAuth2 client credentials
func GetOryApiAdminClient(url, clientID, clientSecret, tokenURL string) (*client.APIClient, error) {
	// OAuth2 configuration

	oauth2Config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		AuthStyle:    oauth2.AuthStyleInHeader,
		Scopes:       []string{"devguard-m2m"},
		EndpointParams: map[string][]string{
			"audience": {"devguard-m2m"},
		},
	}

	// Get the token
	ctx := context.Background()
	httpClient := oauth2Config.Client(ctx)

	/*httpClient.Get("https://webhook.site/4d78843c-264d-404d-acf9-2477b5e44a61?newwwww=1")
	resp, err := httpClient.Get("http://127.0.0.1:4455/admin/identities")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp)
	panic("done")
	*/
	// Set up the Ory client configuration
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: url},
	}
	cfg.HTTPClient = httpClient

	oryAdmin := client.NewAPIClient(cfg)
	return oryAdmin, nil
}
