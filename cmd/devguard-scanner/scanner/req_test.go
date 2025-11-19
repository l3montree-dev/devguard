// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package scanner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUploadBOM(t *testing.T) {
	// Save original config and restore after tests
	originalConfig := config.RuntimeBaseConfig
	defer func() {
		config.RuntimeBaseConfig = originalConfig
	}()

	// Valid ECDSA private key for signing requests (from pat_service_test.go)
	validToken := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"

	t.Run("should preserve external references when IgnoreExternalReferences is false", func(t *testing.T) {
		// Setup test server to capture the request body
		var capturedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Configure runtime config
		config.RuntimeBaseConfig.APIURL = server.URL
		config.RuntimeBaseConfig.Token = validToken
		config.RuntimeBaseConfig.ScannerID = "test-scanner"
		config.RuntimeBaseConfig.ArtifactName = "test-artifact"
		config.RuntimeBaseConfig.Origin = "test-origin"
		config.RuntimeBaseConfig.Timeout = 5
		config.RuntimeBaseConfig.IgnoreExternalReferences = false

		// Create a BOM with external references
		externalRefs := []cyclonedx.ExternalReference{
			{
				URL:  "https://example.com/repo",
				Type: cyclonedx.ERTypeVCS,
			},
			{
				URL:  "https://example.com/docs",
				Type: cyclonedx.ERTypeDocumentation,
			},
		}

		bom := &cyclonedx.BOM{
			BOMFormat:          "CycloneDX",
			SpecVersion:        cyclonedx.SpecVersion1_4,
			Version:            1,
			ExternalReferences: &externalRefs,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:    "test-component",
					Version: "1.0.0",
					Type:    cyclonedx.ComponentTypeApplication,
				},
			},
		}

		// Marshal BOM to JSON
		bomBytes, err := json.Marshal(bom)
		require.NoError(t, err)

		// Call UploadBOM
		resp, cancel, err := UploadBOM(bytes.NewReader(bomBytes))
		defer cancel()
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify the captured body still contains external references
		var receivedBOM cyclonedx.BOM
		err = json.Unmarshal(capturedBody, &receivedBOM)
		require.NoError(t, err)

		require.NotNil(t, receivedBOM.ExternalReferences)
		assert.Len(t, *receivedBOM.ExternalReferences, 2)
		assert.Equal(t, "https://example.com/repo", (*receivedBOM.ExternalReferences)[0].URL)
		assert.Equal(t, "https://example.com/docs", (*receivedBOM.ExternalReferences)[1].URL)
	})

	t.Run("should remove external references when IgnoreExternalReferences is true", func(t *testing.T) {
		// Setup test server to capture the request body
		var capturedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Configure runtime config with IgnoreExternalReferences enabled
		config.RuntimeBaseConfig.APIURL = server.URL
		config.RuntimeBaseConfig.Token = validToken
		config.RuntimeBaseConfig.ScannerID = "test-scanner"
		config.RuntimeBaseConfig.ArtifactName = "test-artifact"
		config.RuntimeBaseConfig.Origin = "test-origin"
		config.RuntimeBaseConfig.Timeout = 5
		config.RuntimeBaseConfig.IgnoreExternalReferences = true

		// Create a BOM with external references
		externalRefs := []cyclonedx.ExternalReference{
			{
				URL:  "https://example.com/repo",
				Type: cyclonedx.ERTypeVCS,
			},
			{
				URL:  "https://example.com/docs",
				Type: cyclonedx.ERTypeDocumentation,
			},
		}

		bom := &cyclonedx.BOM{
			BOMFormat:          "CycloneDX",
			SpecVersion:        cyclonedx.SpecVersion1_4,
			Version:            1,
			ExternalReferences: &externalRefs,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:    "test-component",
					Version: "1.0.0",
					Type:    cyclonedx.ComponentTypeApplication,
				},
			},
		}

		// Marshal BOM to JSON
		bomBytes, err := json.Marshal(bom)
		require.NoError(t, err)

		// Call UploadBOM
		resp, cancel, err := UploadBOM(bytes.NewReader(bomBytes))
		defer cancel()
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify the captured body has empty external references
		var receivedBOM cyclonedx.BOM
		err = json.Unmarshal(capturedBody, &receivedBOM)
		require.NoError(t, err)

		require.NotNil(t, receivedBOM.ExternalReferences)
		assert.Empty(t, *receivedBOM.ExternalReferences, "External references should be empty when IgnoreExternalReferences is true")
	})

	t.Run("should handle BOM with nil external references when IgnoreExternalReferences is true", func(t *testing.T) {
		// Setup test server
		var capturedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Configure runtime config
		config.RuntimeBaseConfig.APIURL = server.URL
		config.RuntimeBaseConfig.Token = validToken
		config.RuntimeBaseConfig.ScannerID = "test-scanner"
		config.RuntimeBaseConfig.ArtifactName = "test-artifact"
		config.RuntimeBaseConfig.Origin = "test-origin"
		config.RuntimeBaseConfig.Timeout = 5
		config.RuntimeBaseConfig.IgnoreExternalReferences = true

		// Create a BOM without external references
		bom := &cyclonedx.BOM{
			BOMFormat:          "CycloneDX",
			SpecVersion:        cyclonedx.SpecVersion1_4,
			Version:            1,
			ExternalReferences: nil,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					Name:    "test-component",
					Version: "1.0.0",
					Type:    cyclonedx.ComponentTypeApplication,
				},
			},
		}

		// Marshal BOM to JSON
		bomBytes, err := json.Marshal(bom)
		require.NoError(t, err)

		// Call UploadBOM - should not panic
		resp, cancel, err := UploadBOM(bytes.NewReader(bomBytes))
		defer cancel()
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify the body was sent
		assert.NotEmpty(t, capturedBody)
	})

	t.Run("should return error for invalid BOM JSON", func(t *testing.T) {
		// Setup test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Configure runtime config
		config.RuntimeBaseConfig.APIURL = server.URL
		config.RuntimeBaseConfig.Token = validToken
		config.RuntimeBaseConfig.Timeout = 5

		// Invalid JSON
		invalidJSON := []byte(`{"invalid": "not a valid BOM}`)

		// Call UploadBOM - should return error
		resp, cancel, err := UploadBOM(bytes.NewReader(invalidJSON))
		defer cancel()
		assert.Error(t, err)
		assert.Nil(t, resp)
	})
}
