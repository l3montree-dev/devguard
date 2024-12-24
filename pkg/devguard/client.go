package devguard

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/l3montree-dev/devguard/internal/core/pat"
)

type HTTPClient struct {
	httpClient *http.Client

	token  string
	apiUrl string
}

func NewHTTPClient(token, apiUrl string) HTTPClient {
	return HTTPClient{
		token:  token,
		apiUrl: apiUrl,
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

	req.URL, err = url.Parse(fmt.Sprintf("%s%s", c.apiUrl, req.URL.Path))

	if err != nil {
		return nil, err
	}

	return c.httpClient.Do(req)
}
