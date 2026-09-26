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

func newTestSimpleIndex(t *testing.T, old, fresh time.Time) []byte {
	t.Helper()
	file := func(name string, uploaded time.Time) map[string]any {
		return map[string]any{
			"filename":    name,
			"url":         "https://files.pythonhosted.org/packages/ab/cd/ef/" + name,
			"hashes":      map[string]string{"sha256": "abc"},
			"upload-time": uploaded.UTC().Format(time.RFC3339Nano),
		}
	}
	index := map[string]any{
		"meta":     map[string]any{"api-version": "1.1"},
		"name":     "charset-normalizer",
		"versions": []string{"3.4.0", "3.5.0", "3.5.1"},
		"files": []any{
			file("charset_normalizer-3.4.0.tar.gz", old),
			file("charset_normalizer-3.4.0-py3-none-any.whl", old),
			file("charset_normalizer-3.5.0.tar.gz", old),
			// wheel of an old release that was uploaded later
			file("charset_normalizer-3.5.0-cp313-cp313-macosx_10_13_universal2.whl", fresh),
			file("charset_normalizer-3.5.1.tar.gz", fresh),
			file("charset_normalizer-3.5.1-py3-none-any.whl", fresh),
		},
	}
	data, err := json.Marshal(index)
	require.NoError(t, err)
	return data
}

func decodeSimpleIndex(t *testing.T, data []byte) ([]string, []string) {
	t.Helper()
	var index pySimple
	require.NoError(t, json.Unmarshal(data, &index))
	files := make([]string, 0, len(index.Files))
	for _, f := range index.Files {
		files = append(files, f.Filename)
	}
	return files, index.Versions
}

func TestFilterPyPiSimpleIndex(t *testing.T) {
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	fresh := now.Add(-1 * time.Hour)
	data := newTestSimpleIndex(t, old, fresh)

	t.Run("passes the version parsed from the filename to keep", func(t *testing.T) {
		seen := map[string]bool{}
		_, err := filterPyPiSimpleIndex(data, func(version string, _ time.Time) bool {
			seen[version] = true
			return true
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"3.4.0": true, "3.5.0": true, "3.5.1": true}, seen)
	})

	t.Run("removes too new files and versions without any remaining file", func(t *testing.T) {
		filtered, err := filterPyPiSimpleIndex(data, func(_ string, published time.Time) bool {
			return time.Since(published) >= 48*time.Hour
		})
		require.NoError(t, err)

		files, versions := decodeSimpleIndex(t, filtered)
		assert.Equal(t, []string{
			"charset_normalizer-3.4.0.tar.gz",
			"charset_normalizer-3.4.0-py3-none-any.whl",
			"charset_normalizer-3.5.0.tar.gz",
		}, files)
		// 3.5.0 keeps its sdist, so it stays listed even though one of its wheels was removed
		assert.Equal(t, []string{"3.4.0", "3.5.0"}, versions)
	})

	t.Run("filters by version", func(t *testing.T) {
		filtered, err := filterPyPiSimpleIndex(data, func(version string, _ time.Time) bool {
			return version != "3.4.0"
		})
		require.NoError(t, err)

		files, versions := decodeSimpleIndex(t, filtered)
		assert.NotContains(t, files, "charset_normalizer-3.4.0.tar.gz")
		assert.NotContains(t, files, "charset_normalizer-3.4.0-py3-none-any.whl")
		assert.Equal(t, []string{"3.5.0", "3.5.1"}, versions)
	})

	t.Run("returns an error for malformed json", func(t *testing.T) {
		_, err := filterPyPiSimpleIndex([]byte("<!DOCTYPE html>"), func(string, time.Time) bool { return true })
		assert.Error(t, err)
	})
}

func TestPyPISimpleIndexRulesMatchVersion(t *testing.T) {
	// the keep function of ProxyPyPISimple checks rules against the purl built from the
	// filename version - make sure a version-specific rule matches it
	blocked, _ := matchRules(pypi.packageIdentifier("charset-normalizer", "3.5.1"), []string{"pkg:pypi/charset-normalizer@3.5.1"})
	assert.True(t, blocked)
	blocked, _ = matchRules(pypi.packageIdentifier("charset-normalizer", "3.5.0"), []string{"pkg:pypi/charset-normalizer@3.5.1"})
	assert.False(t, blocked)
}
