package services

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

		// Override the openSourceInsightsAPIURL to point to the mock server
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
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

		// Override the openSourceInsightsAPIURL to point to the mock server
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		_, err := service.GetVersion(ctx, "golang", "gorm", "1.0.0")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("should replace slashes with colons for maven packages", func(t *testing.T) {
		// Mock server to simulate the deps.dev API
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify that slashes are replaced with colons for Maven packages
			// The package name should be "com.fasterxml.jackson.core:jackson-core" (colons replacing slashes)
			expectedPath := "/systems/maven/packages/com.fasterxml.jackson.core:jackson-core/versions/2.13.0"
			if r.URL.Path != expectedPath {
				t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"versionKey": {"system": "maven", "name": "com.fasterxml.jackson.core:jackson-core", "version": "2.13.0"}}`)) // nolint
		}))
		defer mockServer.Close()

		// Override the openSourceInsightsAPIURL to point to the mock server
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		// Test with a Maven package that has slashes in the name
		_, err := service.GetVersion(ctx, "maven", "com.fasterxml.jackson.core/jackson-core", "2.13.0")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("should not modify package names for non-maven ecosystems", func(t *testing.T) {
		testCases := []struct {
			ecosystem       string
			packageName     string
			expectedSystem  string
			expectedPackage string
		}{
			{"npm", "react/dom", "npm", "react%2Fdom"},                         // npm should keep slashes (URL encoded)
			{"golang", "github.com/test/pkg", "go", "github.com%2Ftest%2Fpkg"}, // golang -> go, keep slashes (URL encoded)
			{"pypi", "django/contrib", "pypi", "django%2Fcontrib"},             // pypi should keep slashes (URL encoded)
		}

		for _, tc := range testCases {
			t.Run(tc.ecosystem+"_"+tc.packageName, func(t *testing.T) {
				// Mock server to simulate the deps.dev API
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					expectedPath := "/systems/" + tc.expectedSystem + "/packages/" + tc.expectedPackage + "/versions/1.0.0"
					actualPath := r.URL.Path
					// Check RawPath for encoded values if Path is unescaped
					if r.URL.RawPath != "" {
						actualPath = r.URL.RawPath
					}
					if actualPath != expectedPath {
						t.Errorf("expected path %s, got %s", expectedPath, actualPath)
						http.Error(w, "Not Found", http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"versionKey": {"system": "` + tc.expectedSystem + `", "name": "` + tc.packageName + `", "version": "1.0.0"}}`)) // nolint
				}))
				defer mockServer.Close()

				// Override the openSourceInsightsAPIURL to point to the mock server
				openSourceInsightsAPIURL = mockServer.URL

				service := NewOpenSourceInsightService()
				ctx := context.Background()

				_, err := service.GetVersion(ctx, tc.ecosystem, tc.packageName, "1.0.0")
				if err != nil {
					t.Fatalf("expected no error for %s/%s, got %v", tc.ecosystem, tc.packageName, err)
				}
			})
		}
	})

	t.Run("should handle multiple slashes in maven package names", func(t *testing.T) {
		// Mock server to simulate the deps.dev API
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify that multiple slashes are all replaced with colons
			// The package name should be "org.springframework:spring-web:core" (all slashes replaced with colons)
			expectedPath := "/systems/maven/packages/org.springframework:spring-web:core/versions/5.3.21"
			if r.URL.Path != expectedPath {
				t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"versionKey": {"system": "maven", "name": "org.springframework:spring-web:core", "version": "5.3.21"}}`)) // nolint
		}))
		defer mockServer.Close()

		// Override the openSourceInsightsAPIURL to point to the mock server
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		// Test with a Maven package that has multiple slashes
		_, err := service.GetVersion(ctx, "maven", "org.springframework/spring-web/core", "5.3.21")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}
