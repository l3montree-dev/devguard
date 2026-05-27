package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	t.Run("should map composer packages through the Packagist transformer", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vendor/package.json" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			w.WriteHeader(http.StatusOK)
			// nolint:errcheck
			w.Write([]byte(`{
				"packages": {
					"vendor/package": [
						{
							"name": "vendor/package",
							"version": "1.0.0",
							"license": ["MIT"]
						},
						{
							"name": "vendor/package",
							"version": "2.0.0",
							"license": ["MIT"],
							"time": "2024-01-02T03:04:05Z",
							"source": {
								"type": "git",
								"url": "https://github.com/acme/package"
							},
							"dist": {
								"type": "zip",
								"url": "https://downloads.example.com/package.zip"
							}
						}
					]
				}
			}`))
		}))
		defer mockServer.Close()

		oldPackagistAPIURL := packagistAPIURL
		packagistAPIURL = mockServer.URL
		t.Cleanup(func() {
			packagistAPIURL = oldPackagistAPIURL
		})

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		response, err := service.GetVersion(ctx, "composer", "vendor/package", "2.0.0")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if response.VersionKey.System != "COMPOSER" {
			t.Fatalf("expected system COMPOSER, got %s", response.VersionKey.System)
		}
		if response.VersionKey.Name != "vendor/package" {
			t.Fatalf("expected name vendor/package, got %s", response.VersionKey.Name)
		}
		if response.VersionKey.Version != "2.0.0" {
			t.Fatalf("expected version 2.0.0, got %s", response.VersionKey.Version)
		}
		if len(response.Licenses) != 1 || response.Licenses[0] != "MIT" {
			t.Fatalf("expected MIT license, got %#v", response.Licenses)
		}
		if len(response.Links) != 2 {
			t.Fatalf("expected 2 links from source and dist, got %d", len(response.Links))
		}
		if len(response.RelatedProjects) != 1 {
			t.Fatalf("expected 1 related project from source metadata, got %d", len(response.RelatedProjects))
		}
	})

	t.Run("should return an error when the Packagist API returns a non-200 status", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vendor/package.json" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer mockServer.Close()

		oldPackagistAPIURL := packagistAPIURL
		packagistAPIURL = mockServer.URL
		t.Cleanup(func() {
			packagistAPIURL = oldPackagistAPIURL
		})

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		_, err := service.GetVersion(ctx, "composer", "vendor/package", "2.0.0")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "could not get version information") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("should return an error when the requested composer version is missing", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vendor/package.json" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			w.WriteHeader(http.StatusOK)
			// nolint:errcheck
			w.Write([]byte(`{
				"packages": {
					"vendor/package": [
						{
							"name": "vendor/package",
							"version": "1.0.0",
							"license": ["MIT"]
						}
					]
				}
			}`))
		}))
		defer mockServer.Close()

		oldPackagistAPIURL := packagistAPIURL
		packagistAPIURL = mockServer.URL
		t.Cleanup(func() {
			packagistAPIURL = oldPackagistAPIURL
		})

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		_, err := service.GetVersion(ctx, "composer", "vendor/package", "2.0.0")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "no version matching specified package version from packagist") {
			t.Fatalf("expected missing version error, got %v", err)
		}
	})

	t.Run("should return an error for malformed composer package names", func(t *testing.T) {
		service := NewOpenSourceInsightService()
		ctx := context.Background()

		_, err := service.GetVersion(ctx, "composer", "vendor", "2.0.0")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid packageName for packagist alternative") {
			t.Fatalf("expected malformed package error, got %v", err)
		}
	})

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
			expectedVersion string
		}{
			{"npm", "react/dom", "npm", "react%2Fdom", "1.0.0"},                          // npm should keep slashes (URL encoded)
			{"golang", "github.com/test/pkg", "go", "github.com%2Ftest%2Fpkg", "v1.0.0"}, // golang -> go, keep slashes (URL encoded)
			{"pypi", "django/contrib", "pypi", "django%2Fcontrib", "1.0.0"},              // pypi should keep slashes (URL encoded)
		}

		for _, tc := range testCases {
			t.Run(tc.ecosystem+"_"+tc.packageName, func(t *testing.T) {
				// Mock server to simulate the deps.dev API
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					expectedPath := "/systems/" + tc.expectedSystem + "/packages/" + tc.expectedPackage + "/versions/" + tc.expectedVersion
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

	t.Run("should prefer v-prefixed go versions", func(t *testing.T) {
		requestedPaths := []string{}
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPaths = append(requestedPaths, r.URL.EscapedPath())
			switch r.URL.EscapedPath() {
			case "/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/v3.4.1":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"versionKey": {"system": "go", "name": "github.com/ProtonMail/gopenpgp/v3", "version": "v3.4.1"}, "licenses": ["MIT"]}`)) // nolint
			default:
				t.Errorf("unexpected path %s", r.URL.EscapedPath())
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		}))
		defer mockServer.Close()

		originalURL := openSourceInsightsAPIURL
		t.Cleanup(func() {
			openSourceInsightsAPIURL = originalURL
		})
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		response, err := service.GetVersion(ctx, "golang", "github.com/ProtonMail/gopenpgp/v3", "3.4.1")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(response.Licenses) != 1 || response.Licenses[0] != "MIT" {
			t.Fatalf("expected MIT license, got %v", response.Licenses)
		}

		expectedPaths := []string{"/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/v3.4.1"}
		if len(requestedPaths) != len(expectedPaths) || requestedPaths[0] != expectedPaths[0] {
			t.Fatalf("expected deps.dev requests %v, got %v", expectedPaths, requestedPaths)
		}
	})

	t.Run("should fall back to go versions without v prefix", func(t *testing.T) {
		requestedPaths := []string{}
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPaths = append(requestedPaths, r.URL.EscapedPath())
			switch r.URL.EscapedPath() {
			case "/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/v3.4.1":
				http.Error(w, "Not Found", http.StatusNotFound)
			case "/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/3.4.1":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"versionKey": {"system": "go", "name": "github.com/ProtonMail/gopenpgp/v3", "version": "3.4.1"}, "licenses": ["MIT"]}`)) // nolint
			default:
				t.Errorf("unexpected path %s", r.URL.EscapedPath())
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		}))
		defer mockServer.Close()

		originalURL := openSourceInsightsAPIURL
		t.Cleanup(func() {
			openSourceInsightsAPIURL = originalURL
		})
		openSourceInsightsAPIURL = mockServer.URL

		service := NewOpenSourceInsightService()
		ctx := context.Background()

		response, err := service.GetVersion(ctx, "golang", "github.com/ProtonMail/gopenpgp/v3", "v3.4.1")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(response.Licenses) != 1 || response.Licenses[0] != "MIT" {
			t.Fatalf("expected MIT license, got %v", response.Licenses)
		}

		expectedPaths := []string{
			"/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/v3.4.1",
			"/systems/go/packages/github.com%2FProtonMail%2Fgopenpgp%2Fv3/versions/3.4.1",
		}
		if len(requestedPaths) != len(expectedPaths) {
			t.Fatalf("expected deps.dev requests %v, got %v", expectedPaths, requestedPaths)
		}
		for i := range expectedPaths {
			if requestedPaths[i] != expectedPaths[i] {
				t.Fatalf("expected deps.dev requests %v, got %v", expectedPaths, requestedPaths)
			}
		}
	})
}
