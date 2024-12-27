package devguard

import (
	"net/http"
	"net/url"

	"github.com/l3montree-dev/devguard/internal/core/pat"
)

type HTTPClient struct {
	httpClient *http.Client

	token  string
	apiUrl *url.URL
}

func NewHTTPClient(token, apiUrl string) HTTPClient {
	u, err := url.Parse(apiUrl)
	if err != nil {
		panic(err)
	}

	return HTTPClient{
		token:  token,
		apiUrl: u,
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
	req.URL.Scheme = c.apiUrl.Scheme
	req.URL.Host = c.apiUrl.Host

	return c.httpClient.Do(req)
}
