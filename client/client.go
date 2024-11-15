package client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/l3montree-dev/devguard/internal/core/pat"
)

type DevGuardClient struct {
	httpClient *http.Client

	token  string
	apiUrl string
}

func NewDevGuardClient(token, apiUrl string) DevGuardClient {
	return DevGuardClient{
		token:  token,
		apiUrl: apiUrl,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

func (c DevGuardClient) Do(req *http.Request) (*http.Response, error) {
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
