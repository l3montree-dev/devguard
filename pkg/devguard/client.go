package devguard

import (
	"net/http"
	"net/url"

	"github.com/l3montree-dev/devguard/internal/core/pat"
)

type HTTPClient struct {
	httpClient *http.Client

	token  string
	apiURL *url.URL
}

func NewHTTPClient(token, apiURL string) HTTPClient {
	u, err := url.Parse(apiURL)
	if err != nil {
		panic(err)
	}

	return HTTPClient{
		token:  token,
		apiURL: u,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

func (c HTTPClient) Do(req *http.Request) (*http.Response, error) {
	err := pat.SignRequest(c.token, req)
	if err != nil {
		return nil, err
	}

	// prepend the api url to the request url
	req.URL.Scheme = c.apiURL.Scheme
	req.URL.Host = c.apiURL.Host

	return c.httpClient.Do(req)
}
