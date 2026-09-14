// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package githubint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/stretchr/testify/assert"
)

// installationReposServer serves GET /installation/repositories with `total`
// repositories paginated at `perPage`, and records which page numbers were
// requested. Repository full names are "acme/repo-<n>" with n starting at 1, so
// a caller can tell exactly which repositories it did and did not receive.
type installationReposServer struct {
	mu             sync.Mutex
	requestedPages []int
}

func (s *installationReposServer) pages() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.requestedPages...)
}

func newInstallationReposClient(t *testing.T, total, perPage int) (githubClient, *installationReposServer) {
	t.Helper()

	recorder := &installationReposServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil {
			page = 1
		}

		recorder.mu.Lock()
		recorder.requestedPages = append(recorder.requestedPages, page)
		// Guard the test itself against the infinite paging loop this test
		// exists to detect - fail loudly instead of hanging the suite.
		tooManyRequests := len(recorder.requestedPages) > 50
		recorder.mu.Unlock()
		if tooManyRequests {
			t.Errorf("fetchAllRepos kept paging: %d requests for %d repositories", 50, total)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		repos := []*github.Repository{}
		// GitHub pagination is 1-indexed.
		start := (page - 1) * perPage
		for i := start; i < start+perPage && i < total; i++ {
			name := fmt.Sprintf("acme/repo-%d", i+1)
			repos = append(repos, &github.Repository{FullName: github.String(name)})
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test server
		json.NewEncoder(w).Encode(struct {
			TotalCount   int                  `json:"total_count"`
			Repositories []*github.Repository `json:"repositories"`
		}{TotalCount: total, Repositories: repos})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL + "/api/v3/")
	assert.NoError(t, err)

	client := github.NewClient(server.Client())
	client.BaseURL = baseURL

	return githubClient{Client: client, githubAppInstallationID: 1}, recorder
}

func fullNames(repos []*github.Repository) []string {
	names := make([]string, 0, len(repos))
	for _, repo := range repos {
		names = append(names, repo.GetFullName())
	}
	return names
}

func TestFetchAllRepos(t *testing.T) {
	t.Run("it should return every repository exactly once when they fit on a single page", func(t *testing.T) {
		client, _ := newInstallationReposClient(t, 3, 100)

		repos, err := fetchAllRepos(context.Background(), client)

		assert.NoError(t, err)
		assert.Equal(t, []string{"acme/repo-1", "acme/repo-2", "acme/repo-3"}, fullNames(repos))
	})

	t.Run("it should return every repository exactly once when they span multiple pages", func(t *testing.T) {
		// 250 repositories at 100 per page is three pages: 100, 100, 50.
		client, recorder := newInstallationReposClient(t, 250, 100)

		repos, err := fetchAllRepos(context.Background(), client)

		assert.NoError(t, err)
		assert.Len(t, repos, 250, "expected all 250 repositories, no duplicates and none dropped")
		assert.Equal(t, []int{1, 2, 3}, recorder.pages(), "each page should be fetched exactly once")

		// Every repository is present exactly once - in particular the tail,
		// which is the page an off-by-one page index silently drops.
		seen := map[string]int{}
		for _, name := range fullNames(repos) {
			seen[name]++
		}
		assert.Len(t, seen, 250)
		for i := 1; i <= 250; i++ {
			name := fmt.Sprintf("acme/repo-%d", i)
			assert.Equal(t, 1, seen[name], "expected %s exactly once, got %d", name, seen[name])
		}
	})

	t.Run("it should stop when a page comes back empty even if total_count disagrees", func(t *testing.T) {
		// total_count is 500 but the server only ever has 120 repositories to
		// hand out, so page 3 onwards is empty. Without a no-progress guard the
		// loop never reaches total_count and pages forever.
		client, _ := newInstallationReposClient(t, 120, 100)
		client.githubAppInstallationID = 2

		mux := http.NewServeMux()
		mux.HandleFunc("/api/v3/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
			page, err := strconv.Atoi(r.URL.Query().Get("page"))
			if err != nil {
				page = 1
			}
			repos := []*github.Repository{}
			start := (page - 1) * 100
			for i := start; i < start+100 && i < 120; i++ {
				repos = append(repos, &github.Repository{FullName: github.String(fmt.Sprintf("acme/repo-%d", i+1))})
			}
			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck // test server
			json.NewEncoder(w).Encode(struct {
				TotalCount   int                  `json:"total_count"`
				Repositories []*github.Repository `json:"repositories"`
			}{TotalCount: 500, Repositories: repos})
		})
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)
		baseURL, err := url.Parse(server.URL + "/api/v3/")
		assert.NoError(t, err)
		inconsistent := github.NewClient(server.Client())
		inconsistent.BaseURL = baseURL

		done := make(chan struct{})
		var repos []*github.Repository
		var fetchErr error
		go func() {
			defer close(done)
			repos, fetchErr = fetchAllRepos(context.Background(), githubClient{Client: inconsistent, githubAppInstallationID: 2})
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("fetchAllRepos did not terminate when total_count overstated the number of repositories")
		}

		assert.NoError(t, fetchErr)
		assert.Len(t, repos, 120)
	})
}
