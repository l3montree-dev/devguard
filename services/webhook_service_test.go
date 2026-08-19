// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWebhookService(url string) *webhookClient {
	webhookClient := NewWebhookService(url, nil)
	webhookClient.retryDelays = []time.Duration{0, 0, 0}
	return webhookClient
}

func TestWebhookClient_CreateRequest_HMACSignature(t *testing.T) {
	const secret = "test-webhook-secret"
	body := `{"event":"dependencyVulnerabilities","severity":"high"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(receivedBody)
		expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

		assert.Equal(t, body, string(receivedBody))
		assert.Equal(t, expectedSignature, r.Header.Get("X-Hub-Signature-256"))
		assert.Equal(t, secret, r.Header.Get("X-Webhook-Secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secretValue := secret
	client := NewWebhookService(server.URL, &secretValue)
	client.retryDelays = []time.Duration{0, 0, 0}

	resp, err := client.CreateRequest(context.Background(), http.MethodPost, server.URL, strings.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestWebhookClient_CreateRequest_DoesNotSignWithoutSecret(t *testing.T) {
	emptySecret := ""
	cases := []struct {
		name   string
		secret *string
	}{
		{name: "nil secret", secret: nil},
		{name: "empty secret", secret: &emptySecret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("X-Hub-Signature-256"))
				assert.Empty(t, r.Header.Get("X-Webhook-Secret"))
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := NewWebhookService(server.URL, tc.secret)
			client.retryDelays = []time.Duration{0, 0, 0}
			resp, err := client.CreateRequest(context.Background(), http.MethodPost, server.URL, strings.NewReader(`{"test":"data"}`))
			require.NoError(t, err)
			require.NotNil(t, resp)
			defer resp.Body.Close()
		})
	}
}

func TestWebhookClient_CreateRequest_ReusesSignatureAcrossRetries(t *testing.T) {
	const secret = "test-webhook-secret"
	body := `{"event":"test"}`
	var signatures []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signatures = append(signatures, r.Header.Get("X-Hub-Signature-256"))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	secretValue := secret
	client := NewWebhookService(server.URL, &secretValue)
	client.retryDelays = []time.Duration{0, 0, 0}
	resp, err := client.CreateRequest(context.Background(), http.MethodPost, server.URL, strings.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()

	require.Len(t, signatures, 3)
	assert.Equal(t, signatures[0], signatures[1])
	assert.Equal(t, signatures[1], signatures[2])
}

func TestWebhookClient_CreateRequest_RetryLogic(t *testing.T) {
	t.Run("should succeed on first attempt when request is successful", func(t *testing.T) {
		attemptCount := 0

		// Setup test server that responds with 200 OK
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "success"}`))
		}))
		defer server.Close()

		client := newTestWebhookService(server.URL)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 1, attemptCount, "Should make only 1 attempt when successful")
		resp.Body.Close()
	})

	t.Run("should retry 3 times on 5xx and return the last response", func(t *testing.T) {
		attemptCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := newTestWebhookService(server.URL)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		require.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, 3, attemptCount, "Should make exactly 3 attempts on 5xx")
	})

	t.Run("should not retry on 4xx client errors", func(t *testing.T) {
		attemptCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		client := newTestWebhookService(server.URL)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		require.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, 1, attemptCount, "Should not retry on 4xx")
	})

	t.Run("should retry on 429 Too Many Requests", func(t *testing.T) {
		attemptCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		client := newTestWebhookService(server.URL)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		require.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, 3, attemptCount, "Should retry on 429")
	})
}
