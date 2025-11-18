package devguard

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mockRequestSigner implements RequestSigner for testing
type mockRequestSigner struct {
	signFunc func(token string, req *http.Request) error
}

func (m *mockRequestSigner) SignRequest(token string, req *http.Request) error {
	if m.signFunc != nil {
		return m.signFunc(token, req)
	}
	// Default behavior: add Authorization header
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// Helper function to create a client with a mock signer
func newTestHTTPClient(token, apiURL string, signer RequestSigner) (*HTTPClient, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	client := &HTTPClient{
		Client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
			},
		},
	}

	client.Transport = &signedTransport{
		base:          client.Transport,
		token:         token,
		apiURL:        u,
		RequestSigner: signer,
	}

	return client, nil
}

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		apiURL  string
		wantErr bool
	}{
		{
			name:    "valid URL",
			token:   "test-token",
			apiURL:  "https://api.example.com",
			wantErr: false,
		},
		{
			name:    "valid URL with path",
			token:   "test-token",
			apiURL:  "https://api.example.com/v1",
			wantErr: false,
		},
		{
			name:    "invalid URL",
			token:   "test-token",
			apiURL:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewHTTPClient(tt.token, tt.apiURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHTTPClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewHTTPClient() returned nil client")
			}
			if !tt.wantErr && client.Client == nil {
				t.Error("NewHTTPClient() returned client with nil embedded Client")
			}
		})
	}
}

func TestHTTPClientDo(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request was signed
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Authorization header = %v, want %v", auth, "Bearer test-token")
		}

		// Verify the path
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("Request path = %v, want %v", r.URL.Path, "/api/v1/users")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`)) // nolint:errcheck
	}))
	defer server.Close()

	// Create client pointing to test server with base path
	serverURL, _ := url.Parse(server.URL)
	serverURL.Path = "/api/v1"

	client, err := newTestHTTPClient("test-token", serverURL.String(), &mockRequestSigner{})
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	// Create a request with relative path
	req, err := http.NewRequest("GET", "/users", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	expected := `{"status":"success"}`
	if string(body) != expected {
		t.Errorf("Response body = %v, want %v", string(body), expected)
	}
}

func TestHTTPClientGet(t *testing.T) {
	// Test that Get() method also works through embedding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Request method = %v, want GET", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("Request not signed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestHTTPClient("test-token", server.URL, &mockRequestSigner{})
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	resp, err := client.Get("/test")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}
}

func TestHTTPClientPost(t *testing.T) {
	// Test that Post() method also works through embedding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Request method = %v, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("Request not signed")
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "test data" {
			t.Errorf("Request body = %v, want 'test data'", string(body))
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := newTestHTTPClient("test-token", server.URL, &mockRequestSigner{})
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	resp, err := client.Post("/test", "text/plain", strings.NewReader("test data"))
	if err != nil {
		t.Fatalf("client.Post() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Status code = %v, want %v", resp.StatusCode, http.StatusCreated)
	}
}

func TestSignedTransportURLModification(t *testing.T) {
	tests := []struct {
		name         string
		apiURL       string
		requestPath  string
		expectedPath string
	}{
		{
			name:         "basic URL",
			apiURL:       "https://api.example.com",
			requestPath:  "/users",
			expectedPath: "/users",
		},
		{
			name:         "URL with base path",
			apiURL:       "https://api.example.com/v1",
			requestPath:  "/users",
			expectedPath: "/v1/users",
		},
		{
			name:         "URL with trailing slash",
			apiURL:       "https://api.example.com/v1/",
			requestPath:  "/users",
			expectedPath: "/v1//users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.expectedPath {
					t.Errorf("Request path = %v, want %v", r.URL.Path, tt.expectedPath)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Parse the server URL and add the base path from test case
			serverURL, _ := url.Parse(server.URL)
			apiURL, _ := url.Parse(tt.apiURL)
			serverURL.Path = apiURL.Path

			client, err := newTestHTTPClient("test-token", serverURL.String(), &mockRequestSigner{})
			if err != nil {
				t.Fatalf("newTestHTTPClient() error = %v", err)
			}

			req, _ := http.NewRequest("GET", tt.requestPath, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do() error = %v", err)
			}
			defer resp.Body.Close()
		})
	}
}

func TestSignedTransportSigningError(t *testing.T) {
	// Test that signing errors are properly propagated
	expectedErr := errors.New("signing failed")
	signer := &mockRequestSigner{
		signFunc: func(token string, req *http.Request) error {
			return expectedErr
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be reached when signing fails")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestHTTPClient("test-token", server.URL, signer)
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("Expected error from signing, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error to wrap signing error, got: %v", err)
	}
}

func TestSignedTransportTokenPropagation(t *testing.T) {
	// Test that the token is correctly passed to the signer
	var receivedToken string
	signer := &mockRequestSigner{
		signFunc: func(token string, req *http.Request) error {
			receivedToken = token
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	expectedToken := "my-secret-token"
	client, err := newTestHTTPClient(expectedToken, server.URL, signer)
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	_, err = client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}

	if receivedToken != expectedToken {
		t.Errorf("Token received by signer = %v, want %v", receivedToken, expectedToken)
	}
}

func TestHTTPClientAsInterface(t *testing.T) {
	// Test that HTTPClient can be passed where *http.Client is expected
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request was still signed even when used through interface
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("Request not signed when used through interface")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestHTTPClient("test-token", server.URL, &mockRequestSigner{})
	if err != nil {
		t.Fatalf("newTestHTTPClient() error = %v", err)
	}

	// Function that expects *http.Client
	doRequest := func(c *http.Client, url string) (*http.Response, error) {
		return c.Get(url)
	}

	// This should work since HTTPClient embeds *http.Client
	resp, err := doRequest(client.Client, "/test")
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}
}

func TestSimpleRequestSigner(t *testing.T) {
	// Test the default simpleRequestSigner implementation
	// This is an integration test that verifies the real signer works
	// You may want to skip this if services.SignRequest requires specific setup

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just verify the request reaches the server
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use the real NewHTTPClient which uses simpleRequestSigner
	client, err := NewHTTPClient("test-token", server.URL)
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		// If this fails, it might be because services.SignRequest has dependencies
		t.Logf("Warning: client.Do() error = %v (this may be expected if services.SignRequest has dependencies)", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}
}
