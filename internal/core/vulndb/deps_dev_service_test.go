package vulndb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetProject(t *testing.T) {
	t.Run("should escape the project id before making the request", func(t *testing.T) {
		// Mock server to simulate the deps.dev API
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawPath != "/projects/github%2Ftest%2Fproject" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"project": {"name": "test/project"}}`)) // nolint
		}))
		defer mockServer.Close()

		// Override the depsDevAPIURL to point to the mock server
		depsDevAPIURL = mockServer.URL

		service := NewDepsDevService()
		ctx := context.Background()

		_, err := service.GetProject(ctx, "github/test/project")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

func TestGetVersion(t *testing.T) {
	t.Run("should correctly build the request URL", func(t *testing.T) {
		// Mock server to simulate the deps.dev API
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if r.URL.Path != "/systems/go/packages/gorm/versions/1.0.0" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"version": {"version": "1.0.0"}}`)) // nolint
		}))
		defer mockServer.Close()

		// Override the depsDevAPIURL to point to the mock server
		depsDevAPIURL = mockServer.URL

		service := NewDepsDevService()
		ctx := context.Background()

		_, err := service.GetVersion(ctx, "golang", "gorm", "1.0.0")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}
