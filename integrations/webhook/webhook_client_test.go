// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package webhook

import (
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

		client := NewWebhookClient(server.URL, nil)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest("POST", server.URL, body)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 1, attemptCount, "Should make only 1 attempt when successful")
		resp.Body.Close()
	})

	t.Run("should make exactly 3 attempts when requests fail", func(t *testing.T) {
		attemptCount := 0

		// Setup test server that always fails
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewWebhookClient(server.URL, nil)
		body := strings.NewReader(`{"test": "data"}`)

		resp, err := client.CreateRequest("POST", server.URL, body)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, 3, attemptCount, "Should make exactly 3 attempts")
		assert.Contains(t, err.Error(), "webhook request failed with no response")
	})
}
