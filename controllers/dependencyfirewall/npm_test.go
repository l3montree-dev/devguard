// Copyright (C) 2026 l3montree GmbH
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

package dependencyfirewall

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMEcosystem(t *testing.T) {
	t.Run("trimPrefix", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/npm/@babel/core",
				expected: "@babel/core",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := npm.trimPrefix(tc.path); got != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, got)
				}
			})
		}
	})

	t.Run("parse metadata path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/lodash")
		if pkg != "lodash" || version != "" {
			t.Fatalf("expected lodash with empty version, got %q and %q", pkg, version)
		}
	})

	t.Run("parse tarball path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/lodash/-/lodash-4.17.21.tgz")
		if pkg != "lodash" || version != "4.17.21" {
			t.Fatalf("expected lodash@4.17.21, got %q@%q", pkg, version)
		}
	})

	t.Run("parse tarball path with trailing slash", func(t *testing.T) {
		pkg, version := npm.parsePackage("/lodash/-/lodash-4.17.21.tgz/")
		if pkg != "lodash" || version != "4.17.21" {
			t.Fatalf("expected lodash@4.17.21, got %q@%q", pkg, version)
		}
	})
	t.Run("parse scoped tarball path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/@babel/core/-/core-7.23.0.tgz")
		if pkg != "@babel/core" || version != "7.23.0" {
			t.Fatalf("expected @babel/core@7.23.0, got %q@%q", pkg, version)
		}
	})
}

func TestFilterNPMMetadataVersions(t *testing.T) {
	now := time.Now()
	old := now.Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	fresh := now.Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	metadata := map[string]any{
		"name":      "test-package",
		"readme":    "kept as is",
		"dist-tags": map[string]string{"latest": "2.0.0", "next": "3.0.0-beta.1", "legacy": "1.0.0"},
		"versions": map[string]any{
			"1.0.0":        map[string]string{"version": "1.0.0"},
			"1.1.0":        map[string]string{"version": "1.1.0"},
			"1.2.0-rc.1":   map[string]string{"version": "1.2.0-rc.1"},
			"2.0.0":        map[string]string{"version": "2.0.0"},
			"3.0.0-beta.1": map[string]string{"version": "3.0.0-beta.1"},
		},
		"time": map[string]string{
			"created":      old,
			"modified":     fresh,
			"1.0.0":        old,
			"1.1.0":        old,
			"1.2.0-rc.1":   old,
			"2.0.0":        fresh,
			"3.0.0-beta.1": fresh,
		},
	}
	jsonData, err := json.Marshal(metadata)
	require.NoError(t, err)

	keepOld := func(version string) bool {
		return version != "2.0.0" && version != "3.0.0-beta.1"
	}

	t.Run("removes rejected versions and repoints latest", func(t *testing.T) {
		filtered, removed, err := filterNPMMetadataVersions(jsonData, keepOld)
		require.NoError(t, err)
		assert.Equal(t, 2, removed)

		var result struct {
			Readme   string                     `json:"readme"`
			DistTags map[string]string          `json:"dist-tags"`
			Versions map[string]json.RawMessage `json:"versions"`
			Time     map[string]string          `json:"time"`
		}
		require.NoError(t, json.Unmarshal(filtered, &result))

		assert.Equal(t, "kept as is", result.Readme)
		// latest falls back to the highest stable version, not the prerelease
		assert.Equal(t, map[string]string{"latest": "1.1.0", "legacy": "1.0.0"}, result.DistTags)
		assert.ElementsMatch(t, []string{"1.0.0", "1.1.0", "1.2.0-rc.1"}, keys(result.Versions))
		assert.NotContains(t, result.Time, "2.0.0")
		assert.Contains(t, result.Time, "created")
	})

	t.Run("returns the original document when nothing is removed", func(t *testing.T) {
		filtered, removed, err := filterNPMMetadataVersions(jsonData, func(string) bool { return true })
		require.NoError(t, err)
		assert.Equal(t, 0, removed)
		assert.Equal(t, jsonData, filtered)
	})

	t.Run("drops dist-tags of removed versions", func(t *testing.T) {
		data := []byte(`{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`)
		filtered, removed, err := filterNPMMetadataVersions(data, func(string) bool { return false })
		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.JSONEq(t, `{"dist-tags":{},"versions":{}}`, string(filtered))
	})

	t.Run("returns an error for malformed metadata", func(t *testing.T) {
		_, _, err := filterNPMMetadataVersions([]byte(`not json`), keepOld)
		assert.Error(t, err)
	})
}

func keys[V any](m map[string]V) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

func TestExtractNPMVersionFromMetadata(t *testing.T) {
	metadata := map[string]any{
		"name": "test-package",
		"versions": map[string]any{
			"1.0.0": map[string]any{
				"_npmUser": map[string]any{
					"name": "paul",
				},
			},
			"1.0.1": map[string]any{
				"_npmUser": map[string]any{
					"name": "alice",
				},
			},
			"1.0.2": map[string]any{
				"_npmUser": map[string]any{
					"name": "paul",
				},
			},
		},
		"time": map[string]any{
			"1.0.0": "2020-01-01T00:00:00Z",
			"1.0.1": "2021-01-01T00:00:00Z",
			"1.0.2": "2022-01-01T00:00:00Z",
		},
	}
	data, err := json.Marshal(metadata)
	assert.NoError(t, err)

	var tests = []struct {
		name    string
		version string
		want    bool
	}{
		{name: "no publisher before", version: "1.0.0", want: false},
		{name: "publisher changed", version: "1.0.1", want: true},
		{name: "publisher changed again", version: "1.0.2", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := ExtractNPMPackageFromMetadata(data, tt.version)
			require.NoError(t, err)

			assert.Equal(t, tt.want, pkg.Publisher.ChangedSinceLastVersion)
		})
	}
}
