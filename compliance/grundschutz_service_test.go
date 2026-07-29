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

package compliance

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToRawGithubURL(t *testing.T) {
	assert.Equal(t, "https://raw.githubusercontent.com/foo/bar/refs/heads/main/defs.csv",
		toRawGithubURL("https://github.com/foo/bar/tree/main/defs.csv"))

	raw := "https://raw.githubusercontent.com/foo/bar/refs/heads/main/defs.csv"
	assert.Equal(t, raw, toRawGithubURL(raw))
}

// newCSVTestServer serves body with the given status and counts hits.
func newCSVTestServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		csvCacheMu.Lock()
		csvCache = make(map[string]csvCacheEntry)
		csvCacheMu.Unlock()
	})
	return server, &hits
}

func TestFetchCSVRecords(t *testing.T) {
	t.Run("parses CSV records and caches them, fetching only once", func(t *testing.T) {
		server, hits := newCSVTestServer(t, http.StatusOK, "term,Definition\nfoo,a foo thing\n")

		records, err := fetchCSVRecords(server.URL)
		require.NoError(t, err)
		assert.Equal(t, [][]string{{"term", "Definition"}, {"foo", "a foo thing"}}, records)

		_, err = fetchCSVRecords(server.URL)
		require.NoError(t, err)
		assert.Equal(t, int32(1), hits.Load(), "expected exactly one HTTP request for a cached URL")
	})

	t.Run("coalesces concurrent requests via singleflight", func(t *testing.T) {
		server, hits := newCSVTestServer(t, http.StatusOK, "term,Definition\nfoo,a foo thing\n")

		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := fetchCSVRecords(server.URL)
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		assert.Equal(t, int32(1), hits.Load(), "expected concurrent callers to coalesce into a single HTTP request")
	})

	t.Run("caches a failed fetch, retrying only once", func(t *testing.T) {
		server, hits := newCSVTestServer(t, http.StatusNotFound, "")

		for range 5 {
			_, err := fetchCSVRecords(server.URL)
			assert.Error(t, err)
		}
		assert.Equal(t, int32(1), hits.Load(), "a failing URL should only ever be fetched once, not retried on every call")
	})
}

func TestEnrichProp(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		withNs  bool
		wantDef map[string]string
	}{
		{"no namespace", "foo", false, map[string]string{}},
		{"matching words", "foo,bar", true, map[string]string{"foo": "a foo thing", "bar": "a bar thing"}},
		{"no matching word", "baz", true, map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prop := oscalTypes.Property{Name: "sec_level", Value: tt.value}
			if tt.withNs {
				server, _ := newCSVTestServer(t, http.StatusOK, "term,Definition\nfoo,a foo thing\nbar,a bar thing\n")
				prop.Ns = server.URL
			}

			result, ok := enrichProp(prop).(newProperty)
			require.True(t, ok)
			assert.Equal(t, tt.wantDef, result.Definitions)
		})
	}
}

func TestLoadGrundschutzControls(t *testing.T) {
	controls, err := loadGrundschutzControls()
	require.NoError(t, err)
	assert.NotEmpty(t, controls, "expected the embedded Grundschutz++ catalog to yield at least one control")
	for _, c := range controls {
		assert.Equal(t, "Grundschutz++", c.Framework)
		assert.NotEmpty(t, c.ControlID)
	}
}
