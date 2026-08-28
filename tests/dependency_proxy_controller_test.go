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

package tests

import (
	"encoding/json"
	"testing"

	"github.com/l3montree-dev/devguard/controllers/dependencyfirewall"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyProxyControllerExtractNPMVersion(t *testing.T) {
	tempDir := t.TempDir()

	config := dependencyfirewall.DependencyProxyCache{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := dependencyfirewall.NewDependencyProxyController(nil, config, checker, nil, nil, nil)
	npmController := dependencyfirewall.NewNPMDependencyProxyController(controller)

	t.Run("Extract version from npm package metadata", func(t *testing.T) {
		// Create sample NPM package metadata JSON
		metadata := map[string]any{
			"name": "test-package",
			"dist-tags": map[string]string{
				"latest": "1.2.3",
				"next":   "2.0.0-beta.1",
			},
			"versions": map[string]any{
				"1.2.3": map[string]string{
					"name":    "test-package",
					"version": "1.2.3",
				},
			},
		}

		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		version, _ := npmController.ExtractNPMVersionAndReleaseTimeFromMetadata(jsonData)
		assert.Equal(t, "1.2.3", version)
	})

	t.Run("Extract version from malformed metadata", func(t *testing.T) {
		invalidJSON := []byte(`{"name": "test", "dist-tags": "invalid"}`)
		version, _ := npmController.ExtractNPMVersionAndReleaseTimeFromMetadata(invalidJSON)
		assert.Equal(t, "", version)
	})

	t.Run("Extract version when dist-tags missing", func(t *testing.T) {
		metadata := map[string]any{
			"name": "test-package",
		}
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		version, _ := npmController.ExtractNPMVersionAndReleaseTimeFromMetadata(jsonData)
		assert.Equal(t, "", version)
	})
}
