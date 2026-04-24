// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

		client := NewWebhookService(server.URL, nil)
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

		client := NewWebhookService(server.URL, nil)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assert.Equal(t, 3, attemptCount, "Should make exactly 3 attempts on 5xx")
		if resp != nil {
			resp.Body.Close()
		}
	})

	t.Run("should not retry on 4xx client errors", func(t *testing.T) {
		attemptCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		client := NewWebhookService(server.URL, nil)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, 1, attemptCount, "Should not retry on 4xx")
		if resp != nil {
			resp.Body.Close()
		}
	})

	t.Run("should retry on 429 Too Many Requests", func(t *testing.T) {
		attemptCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		client := NewWebhookService(server.URL, nil)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest(context.Background(), "POST", server.URL, body)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, 3, attemptCount, "Should retry on 429")
		if resp != nil {
			resp.Body.Close()
		}
	})
}
