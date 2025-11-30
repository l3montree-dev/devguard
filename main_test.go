package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMaliciousPackageChecker tests the malicious package detection
func TestMaliciousPackageChecker(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := t.TempDir()
	maliciousDir := filepath.Join(tempDir, "npm", "test-malicious-package")
	if err := os.MkdirAll(maliciousDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create a test malicious package entry
	testEntry := MaliciousPackageEntry{
		ID:      "MAL-TEST-001",
		Summary: "Test malicious package",
		Details: "This is a test entry for malicious package detection",
		Affected: []Affected{
			{
				Package: Package{
					Ecosystem: "npm",
					Name:      "test-malicious-package",
				},
				Versions: []string{"1.0.0", "1.0.1"},
			},
		},
		Published: time.Now().Format(time.RFC3339),
	}

	// Write the test entry to a JSON file
	entryPath := filepath.Join(maliciousDir, "MAL-TEST-001.json")
	data, err := json.MarshalIndent(testEntry, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test entry: %v", err)
	}
	if err := os.WriteFile(entryPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test entry: %v", err)
	}

	// Create the checker
	checker, err := NewMaliciousPackageChecker(tempDir)
	if err != nil {
		t.Fatalf("Failed to create malicious package checker: %v", err)
	}

	tests := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		expected  bool
	}{
		{
			name:      "Malicious package with specific version",
			ecosystem: "npm",
			pkgName:   "test-malicious-package",
			version:   "1.0.0",
			expected:  true,
		},
		{
			name:      "Malicious package with another version",
			ecosystem: "npm",
			pkgName:   "test-malicious-package",
			version:   "1.0.1",
			expected:  true,
		},
		{
			name:      "Malicious package without version",
			ecosystem: "npm",
			pkgName:   "test-malicious-package",
			version:   "",
			expected:  true,
		},
		{
			name:      "Safe package",
			ecosystem: "npm",
			pkgName:   "lodash",
			version:   "4.17.21",
			expected:  false,
		},
		{
			name:      "Wrong ecosystem",
			ecosystem: "go",
			pkgName:   "test-malicious-package",
			version:   "1.0.0",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isMalicious, entry := checker.IsMalicious(tt.ecosystem, tt.pkgName, tt.version)
			if isMalicious != tt.expected {
				t.Errorf("IsMalicious(%s, %s, %s) = %v, want %v",
					tt.ecosystem, tt.pkgName, tt.version, isMalicious, tt.expected)
			}
			if isMalicious && entry == nil {
				t.Error("Expected entry to be non-nil for malicious package")
			}
			if !isMalicious && entry != nil {
				t.Error("Expected entry to be nil for safe package")
			}
		})
	}
}

// TestProxyServerBlocksMaliciousPackages tests that the proxy blocks malicious packages
func TestProxyServerBlocksMaliciousPackages(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := t.TempDir()
	maliciousDir := filepath.Join(tempDir, "npm", "evil-package")
	if err := os.MkdirAll(maliciousDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create a test malicious package entry
	testEntry := MaliciousPackageEntry{
		ID:      "MAL-TEST-002",
		Summary: "Evil package that steals data",
		Details: "This package contains malicious code",
		Affected: []Affected{
			{
				Package: Package{
					Ecosystem: "npm",
					Name:      "evil-package",
				},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "0", Fixed: ""},
						},
					},
				},
			},
		},
		Published: time.Now().Format(time.RFC3339),
	}

	entryPath := filepath.Join(maliciousDir, "MAL-TEST-002.json")
	data, err := json.MarshalIndent(testEntry, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test entry: %v", err)
	}
	if err := os.WriteFile(entryPath, data, 0644); err != nil {
		t.Fatalf("Failed to write test entry: %v", err)
	}

	// Create the checker
	checker, err := NewMaliciousPackageChecker(tempDir)
	if err != nil {
		t.Fatalf("Failed to create malicious package checker: %v", err)
	}

	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a simple package metadata
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    "evil-package",
			"version": "1.0.0",
		}); err != nil {
			t.Fatalf("Failed to write upstream response: %v", err)
		}
	}))
	defer upstream.Close()

	// Create the proxy server
	proxy := NewProxyServer(NPMProxy, t.TempDir(), upstream.URL, checker)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		shouldBlock    bool
	}{
		{
			name:           "Malicious package is blocked",
			path:           "/evil-package",
			expectedStatus: http.StatusForbidden,
			shouldBlock:    true,
		},
		{
			name:           "Safe package is allowed",
			path:           "/lodash",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
		},
		{
			name:           "Health check always works",
			path:           "/health",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()

			proxy.handleRequest(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.shouldBlock {
				// Check response body for block message
				body, _ := io.ReadAll(rec.Body)
				var response map[string]interface{}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				if response["blocked"] != true {
					t.Error("Expected blocked=true in response")
				}
				if response["error"] != "Forbidden" {
					t.Errorf("Expected error=Forbidden, got %v", response["error"])
				}

				// Check header
				if rec.Header().Get("X-Malicious-Package") != "blocked" {
					t.Error("Expected X-Malicious-Package header to be 'blocked'")
				}
			}
		})
	}
}

// TestPackagePathParsing tests the package name/version extraction from paths
func TestPackagePathParsing(t *testing.T) {
	proxy := NewProxyServer(NPMProxy, "", "", nil)

	tests := []struct {
		name            string
		proxyType       ProxyType
		path            string
		expectedPkg     string
		expectedVersion string
	}{
		{
			name:            "NPM package metadata",
			proxyType:       NPMProxy,
			path:            "/lodash",
			expectedPkg:     "lodash",
			expectedVersion: "",
		},
		{
			name:            "NPM scoped package",
			proxyType:       NPMProxy,
			path:            "/@babel/core",
			expectedPkg:     "@babel/core",
			expectedVersion: "",
		},
		{
			name:            "NPM tarball with version",
			proxyType:       NPMProxy,
			path:            "/lodash/-/lodash-4.17.21.tgz",
			expectedPkg:     "lodash",
			expectedVersion: "4.17.21",
		},
		{
			name:            "Go module info",
			proxyType:       GoProxy,
			path:            "/github.com/gin-gonic/gin/@v/v1.9.0.info",
			expectedPkg:     "github.com/gin-gonic/gin/",
			expectedVersion: "v1.9.0",
		},
		{
			name:            "Go module list",
			proxyType:       GoProxy,
			path:            "/github.com/gin-gonic/gin/@v/list",
			expectedPkg:     "github.com/gin-gonic/gin/",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy.proxyType = tt.proxyType
			pkg, version := proxy.parsePackageFromPath(tt.path)

			if pkg != tt.expectedPkg {
				t.Errorf("Expected package %q, got %q", tt.expectedPkg, pkg)
			}
			if version != tt.expectedVersion {
				t.Errorf("Expected version %q, got %q", tt.expectedVersion, version)
			}
		})
	}
}

// TestEndToEndWithRealMaliciousDatabase tests against the actual malicious package database
// This test is skipped by default and can be run manually with: go test -v -run TestEndToEnd
func TestEndToEndWithRealMaliciousDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	// Check if the malicious package database exists
	if _, err := os.Stat(maliciousPackageDir); os.IsNotExist(err) {
		t.Skip("Malicious package database not found, skipping test")
	}

	// Create the checker with real database
	checker, err := NewMaliciousPackageChecker(maliciousPackageDir)
	if err != nil {
		t.Fatalf("Failed to create malicious package checker: %v", err)
	}

	// Test some known malicious packages
	testCases := []struct {
		ecosystem string
		pkgName   string
		expected  bool
	}{
		{"npm", "adv-discord-utility", true},
		{"go", "github.com/boltdb-go/bolt", true},
		{"npm", "lodash", false},  // Known safe package
		{"npm", "express", false}, // Known safe package
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s/%s", tc.ecosystem, tc.pkgName), func(t *testing.T) {
			isMalicious, entry := checker.IsMalicious(tc.ecosystem, tc.pkgName, "")
			if isMalicious != tc.expected {
				t.Errorf("Package %s/%s: expected malicious=%v, got %v",
					tc.ecosystem, tc.pkgName, tc.expected, isMalicious)
				if isMalicious && entry != nil {
					t.Logf("Details: %s", entry.Summary)
				}
			}
		})
	}

	// Test scoped packages separately with better error messages
	t.Run("scoped-packages", func(t *testing.T) {
		// Scoped packages might be stored with or without @ prefix
		scopedPkgs := []string{"@discord-external", "discord-external"}
		found := false
		for _, pkg := range scopedPkgs {
			if isMal, _ := checker.IsMalicious("npm", pkg, ""); isMal {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Note: @discord-external not found in database (may have been removed or renamed)")
		}
	})
}
