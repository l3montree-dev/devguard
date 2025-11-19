package devguard

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/l3montree-dev/devguard/services"
)

type RequestSigner interface {
	SignRequest(token string, req *http.Request) error
}

type simpleRequestSigner struct{}

func (s *simpleRequestSigner) SignRequest(token string, req *http.Request) error {
	return services.SignRequest(token, req)
}

// HTTPClient wraps http.Client with automatic request signing and URL handling
type HTTPClient struct {
	*http.Client // Embedded client provides all http.Client methods
}

// NewHTTPClient creates a new HTTPClient with the given token and API URL
func NewHTTPClient(token, apiURL string) (*HTTPClient, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API URL: %w", err)
	}

	client := &HTTPClient{
		Client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
			},
		},
	}

	// Wrap the transport to intercept all requests
	client.Transport = &signedTransport{
		base:          client.Transport,
		token:         token,
		apiURL:        u,
		RequestSigner: &simpleRequestSigner{},
	}

	return client, nil
}

// signedTransport wraps an http.RoundTripper to add signing and URL modification
type signedTransport struct {
	base   http.RoundTripper
	token  string
	apiURL *url.URL
	RequestSigner
}

// RoundTrip implements http.RoundTripper
func (t *signedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())

	// Sign the request
	if err := t.SignRequest(t.token, req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Modify the URL
	req.URL.Scheme = t.apiURL.Scheme
	req.URL.Host = t.apiURL.Host

	// If the API URL has a base path, prepend it
	if t.apiURL.Path != "" && t.apiURL.Path != "/" {
		req.URL.Path = t.apiURL.Path + req.URL.Path
	}

	return t.base.RoundTrip(req)
}
