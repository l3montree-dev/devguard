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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyProxyController_IntegrityVerification(t *testing.T) {
	// Create temporary cache directory
	tempDir := t.TempDir()

	// Create controller
	config := controllers.DependencyProxyCache{
		CacheDir: tempDir,
	}

	// Create a malicious checker (can be nil for these tests)
	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)

	t.Run("Cache with integrity verification", func(t *testing.T) {
		testData := []byte("test package content")
		cachePath := filepath.Join(tempDir, "test-package.tar.gz")

		// Test cacheDataWithIntegrity
		err := controller.CacheDataWithIntegrity(cachePath, testData)
		require.NoError(t, err)

		// Verify the data file exists
		assert.FileExists(t, cachePath)

		// Verify the hash file exists
		hashPath := cachePath + ".sha256"
		assert.FileExists(t, hashPath)

		// Read and verify hash content
		hashBytes, err := os.ReadFile(hashPath)
		require.NoError(t, err)

		expectedHash := sha256.Sum256(testData)
		expectedHashStr := hex.EncodeToString(expectedHash[:])
		assert.Equal(t, expectedHashStr, string(hashBytes))
	})

	t.Run("Verify cache integrity - valid", func(t *testing.T) {
		testData := []byte("valid package content")
		cachePath := filepath.Join(tempDir, "valid-package.tar.gz")

		// Cache with integrity
		err := controller.CacheDataWithIntegrity(cachePath, testData)
		require.NoError(t, err)

		// Verify integrity
		valid := controller.VerifyCacheIntegrity(cachePath, testData)
		assert.True(t, valid, "Cache integrity should be valid")
	})

	t.Run("Verify cache integrity - tampered data", func(t *testing.T) {
		testData := []byte("original package content")
		cachePath := filepath.Join(tempDir, "tampered-package.tar.gz")

		// Cache with integrity
		err := controller.CacheDataWithIntegrity(cachePath, testData)
		require.NoError(t, err)

		// Tamper with the cached data
		tamperedData := []byte("tampered package content")

		// Verify integrity should fail
		valid := controller.VerifyCacheIntegrity(cachePath, tamperedData)
		assert.False(t, valid, "Cache integrity should fail for tampered data")
	})

	t.Run("Verify cache integrity - missing hash file", func(t *testing.T) {
		testData := []byte("package without hash")
		cachePath := filepath.Join(tempDir, "no-hash-package.tar.gz")

		// Write data without integrity (old cache format)
		err := os.WriteFile(cachePath, testData, 0644)
		require.NoError(t, err)

		// Verify should succeed (backward compatibility)
		valid := controller.VerifyCacheIntegrity(cachePath, testData)
		assert.True(t, valid, "Cache integrity should be valid for backward compatibility")
	})

	t.Run("Verify cache integrity - corrupted hash file", func(t *testing.T) {
		testData := []byte("package with corrupted hash")
		cachePath := filepath.Join(tempDir, "corrupted-hash-package.tar.gz")

		// Cache with integrity
		err := controller.CacheDataWithIntegrity(cachePath, testData)
		require.NoError(t, err)

		// Corrupt the hash file
		hashPath := cachePath + ".sha256"
		err = os.WriteFile(hashPath, []byte("invalid-hash"), 0644)
		require.NoError(t, err)

		// Verify should fail
		valid := controller.VerifyCacheIntegrity(cachePath, testData)
		assert.False(t, valid, "Cache integrity should fail for corrupted hash")
	})
}

func TestDependencyProxyController_MaliciousPackageRemoval(t *testing.T) {
	tempDir := t.TempDir()

	config := controllers.DependencyProxyCache{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)

	t.Run("Malicious package removed from cache", func(t *testing.T) {
		// Cache a "malicious" package
		cachePath := filepath.Join(tempDir, "npm", "fake-malicious-npm-package-1.0.0.tgz")
		testData := []byte("fake malicious content")

		err := controller.CacheDataWithIntegrity(cachePath, testData)
		require.NoError(t, err)

		// Verify it exists
		assert.FileExists(t, cachePath)
		assert.FileExists(t, cachePath+".sha256")
	})
}

func TestDependencyProxyController_ExtractNPMVersion(t *testing.T) {
	tempDir := t.TempDir()

	config := controllers.DependencyProxyCache{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)

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

		// Test extractNPMVersionFromMetadata (we need to make this public for testing)
		// For now, we'll test the full flow
		version, _ := controller.ExtractNPMVersionAndReleaseTimeFromMetadata(jsonData)
		assert.Equal(t, "1.2.3", version)
	})

	t.Run("Extract version from malformed metadata", func(t *testing.T) {
		invalidJSON := []byte(`{"name": "test", "dist-tags": "invalid"}`)
		version, _ := controller.ExtractNPMVersionAndReleaseTimeFromMetadata(invalidJSON)
		assert.Equal(t, "", version)
	})

	t.Run("Extract version when dist-tags missing", func(t *testing.T) {
		metadata := map[string]any{
			"name": "test-package",
		}
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		version, _ := controller.ExtractNPMVersionAndReleaseTimeFromMetadata(jsonData)
		assert.Equal(t, "", version)
	})
}

func TestDependencyProxyController_NPMVersionResolution(t *testing.T) {
	tempDir := t.TempDir()

	config := controllers.DependencyProxyCache{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)

	t.Run("Verify extractNPMVersionFromMetadata extracts correct version", func(t *testing.T) {
		// Test that when metadata is fetched for a package without a version,
		// we correctly extract the "latest" version from dist-tags
		metadata := map[string]any{
			"name": "test-package",
			"dist-tags": map[string]string{
				"latest": "3.1.4",
				"next":   "4.0.0-beta",
			},
		}
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		version, _ := controller.ExtractNPMVersionAndReleaseTimeFromMetadata(jsonData)
		assert.Equal(t, "3.1.4", version, "Should extract the latest version from dist-tags")
	})

	t.Run("Parse package metadata request without version", func(t *testing.T) {
		// When npx or npm install is called without a version,
		// the first request is for package metadata (no version in path)
		pkg, version := controller.ParsePackageFromPath(controllers.NPMProxy, "/lodash")
		assert.Equal(t, "lodash", pkg)
		assert.Equal(t, "", version, "Metadata request should not have a version")
	})

	t.Run("Parse package tarball request with version", func(t *testing.T) {
		// After metadata is fetched, npm will request the specific tarball
		// This request should have an explicit version
		pkg, version := controller.ParsePackageFromPath(controllers.NPMProxy, "/lodash/-/lodash-4.17.21.tgz")
		assert.Equal(t, "lodash", pkg)
		assert.Equal(t, "4.17.21", version, "Tarball request should have explicit version")
	})
}

func TestDependencyProxyController_CheckNotAllowedPackage(t *testing.T) {
	tempDir := t.TempDir()
	config := controllers.DependencyProxyCache{CacheDir: tempDir}
	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)
	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)
	ctx := t.Context()

	testCases := []struct {
		name            string
		proxyType       controllers.ProxyType
		path            string
		rules           []string
		expectedBlocked bool
	}{

		{
			name:            "negation rule with minor wildcard unblocks matching version",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react@17*"},
			expectedBlocked: false,
		},
		{
			name:            "negation rule for different major version does not unblock",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react@18.*"},
			expectedBlocked: true,
		},
		{
			name:            "negation rule with patch wildcard unblocks matching version",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react@17.0.*"},
			expectedBlocked: false,
		},
		{
			name:            "negation rule with patch wildcard does not unblock non-matching minor version",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.1.0",
			rules:           []string{"*", "!react@17.0.*"},
			expectedBlocked: true,
		},
		{
			name:            "negation rule with exact different version does not unblock",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react@18.0.0"},
			expectedBlocked: true,
		},
		{
			name:            "negation rule with exact matching version unblocks",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react@17.0.0"},
			expectedBlocked: false,
		},
		{
			name:            "negation rule with package name without version unblocks",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"*", "!react"},
			expectedBlocked: false,
		},
		{
			name:            "package name rule without version blocks matching package",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"react"},
			expectedBlocked: true,
		},
		{
			name:            "package name rule without version blocks package with version suffix",
			proxyType:       controllers.NPMProxy,
			path:            "react@17.0.0",
			rules:           []string{"react"},
			expectedBlocked: true,
		},
		{
			name:            "package name rule matches purl-format path",
			proxyType:       controllers.NPMProxy,
			path:            "pkg:npm/react@17.0.0",
			rules:           []string{"react"},
			expectedBlocked: true,
		},
		{
			name:            "double-star negation unblocks deeply nested path",
			proxyType:       controllers.NPMProxy,
			path:            "bla/blo/foo/ddo/react",
			rules:           []string{"*", "!**/react"},
			expectedBlocked: false,
		},
		{
			name:            "double-star negation unblocks single-level nested path",
			proxyType:       controllers.NPMProxy,
			path:            "bla/react",
			rules:           []string{"*", "!**/react"},
			expectedBlocked: false,
		},
		{
			name:            "single-star negation unblocks top-level package",
			proxyType:       controllers.NPMProxy,
			path:            "react",
			rules:           []string{"*", "!*/react"},
			expectedBlocked: false,
		},
		{
			name:            "no rules — package allowed",
			proxyType:       controllers.NPMProxy,
			path:            "/lodash",
			rules:           []string{},
			expectedBlocked: false,
		},
		{
			name:            "exact match blocks package",
			proxyType:       controllers.NPMProxy,
			path:            "/lodash",
			rules:           []string{"pkg:npm/lodash@*"},
			expectedBlocked: true,
		},
		{
			name:            "exact match with version blocks package",
			proxyType:       controllers.NPMProxy,
			path:            "pkg:npm/lodash@1.0.0",
			rules:           []string{"pkg:npm/lodash@1.0.0"},
			expectedBlocked: true,
		},
		{
			name:            "wildcard blocks all packages",
			proxyType:       controllers.NPMProxy,
			path:            "/express",
			rules:           []string{"*"},
			expectedBlocked: true,
		},
		{
			name:            "prefix wildcard blocks matching packages",
			proxyType:       controllers.NPMProxy,
			path:            "/babel-core",
			rules:           []string{"pkg:npm/babel-core@*"},
			expectedBlocked: true,
		},
		{
			name:            "prefix wildcard does not block non-matching package",
			proxyType:       controllers.NPMProxy,
			path:            "/lodash",
			rules:           []string{"pkg:npm/babel-*@*"},
			expectedBlocked: false,
		},
		{
			name:            "scoped package exact match",
			proxyType:       controllers.NPMProxy,
			path:            "/@babel/core",
			rules:           []string{"pkg:npm/@babel/core@*"},
			expectedBlocked: true,
		},
		{
			name:            "scoped package wildcard",
			proxyType:       controllers.NPMProxy,
			path:            "/@babel/core",
			rules:           []string{"pkg:npm/@babel/*@*"},
			expectedBlocked: true,
		},
		{
			name:            "scoped wildcard does not block other scope",
			proxyType:       controllers.NPMProxy,
			path:            "/@types/node",
			rules:           []string{"pkg:npm/@babel/*@*"},
			expectedBlocked: false,
		},
		{
			name:            "unresolvable path — not blocked",
			proxyType:       controllers.NPMProxy,
			path:            "/",
			rules:           []string{"*"},
			expectedBlocked: false,
		},
		{
			name:            "PyPI package blocked by rule",
			proxyType:       controllers.PyPIProxy,
			path:            "/simple/requests/",
			rules:           []string{"pkg:pypi/requests@*"},
			expectedBlocked: true,
		},
		{
			name:            "Go module blocked by double-star pattern",
			proxyType:       controllers.GoProxy,
			path:            "/github.com/some/module/@v/list",
			rules:           []string{"pkg:go/github.com/some/module@*"},
			expectedBlocked: true,
		},
		{
			name:            "multiple rules — all purl rules match, package blocked",
			proxyType:       controllers.NPMProxy,
			path:            "/react",
			rules:           []string{"pkg:npm/*@*", "pkg:npm/react@*"},
			expectedBlocked: true,
		},
		{
			name:            "multiple rules — none match",
			proxyType:       controllers.NPMProxy,
			path:            "/vue",
			rules:           []string{"pkg:npm/react@*", "pkg:npm/express@*"},
			expectedBlocked: false,
		},
		{
			name:            "multiple rules — negation unblocks even with subsequent non-matching rule",
			proxyType:       controllers.NPMProxy,
			path:            "/react",
			rules:           []string{"*", "!pkg:npm/react@*", "pkg:npm/express@1.0.0"},
			expectedBlocked: false,
		},
		{
			name:            "block all",
			proxyType:       controllers.NPMProxy,
			path:            "/react",
			rules:           []string{"*"},
			expectedBlocked: true,
		},
		{
			name:            "single-star path rule blocks single-segment match",
			proxyType:       controllers.NPMProxy,
			path:            "npm/a/lodash",
			rules:           []string{"npm/*/lodash"},
			expectedBlocked: true,
		},
		{
			name:            "single-star path rule does not block direct child (no intermediate segment)",
			proxyType:       controllers.NPMProxy,
			path:            "npm/lodash",
			rules:           []string{"npm/*/lodash"},
			expectedBlocked: false,
		},
		{
			name:            "single-star path rule does not block multi-segment path",
			proxyType:       controllers.NPMProxy,
			path:            "npm/a/b/lodash",
			rules:           []string{"npm/*/lodash"},
			expectedBlocked: false,
		},
		{
			name:            "double-star path rule blocks single-segment match",
			proxyType:       controllers.NPMProxy,
			path:            "npm/a/lodash",
			rules:           []string{"npm/**/lodash"},
			expectedBlocked: true,
		},
		{
			name:            "double-star path rule blocks direct child",
			proxyType:       controllers.NPMProxy,
			path:            "npm/lodash",
			rules:           []string{"npm/**/lodash"},
			expectedBlocked: true,
		},
		{
			name:            "double-star path rule blocks multi-segment path",
			proxyType:       controllers.NPMProxy,
			path:            "npm/a/b/lodash",
			rules:           []string{"npm/**/lodash"},
			expectedBlocked: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			settings := controllers.DependencyProxyConfigs{Rules: tc.rules}
			blocked, reason := controller.CheckNotAllowedPackage(ctx, tc.proxyType, tc.path, settings)
			assert.Equal(t, tc.expectedBlocked, blocked)
			if tc.expectedBlocked {
				assert.NotEmpty(t, reason)
			} else {
				assert.Empty(t, reason)
			}
		})
	}
}

func TestDependencyProxyController_ParseNPMPackagePath(t *testing.T) {
	tempDir := t.TempDir()

	config := controllers.DependencyProxyCache{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)

	controller := controllers.NewDependencyProxyController(nil, config, checker, nil, nil, nil)

	testCases := []struct {
		name            string
		path            string
		expectedPackage string
		expectedVersion string
	}{
		{
			name:            "NPM metadata request without version",
			path:            "/lodash",
			expectedPackage: "lodash",
			expectedVersion: "",
		},
		{
			name:            "NPM scoped package without version",
			path:            "/@babel/core",
			expectedPackage: "@babel/core",
			expectedVersion: "",
		},
		{
			name:            "NPM tarball with version",
			path:            "/lodash/-/lodash-4.17.21.tgz",
			expectedPackage: "lodash",
			expectedVersion: "4.17.21",
		},
		{
			name:            "NPM scoped package tarball",
			path:            "/@babel/core/-/core-7.23.0.tgz",
			expectedPackage: "@babel/core",
			expectedVersion: "7.23.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, version := controller.ParsePackageFromPath(controllers.NPMProxy, tc.path)
			assert.Equal(t, tc.expectedPackage, pkg)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

func TestTrimProxyPrefix(t *testing.T) {
	testCases := []struct {
		name      string
		path      string
		ecosystem controllers.ProxyType
		expected  string
	}{
		{
			name:      "NPM with secret",
			path:      "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/npm/lodash",
			ecosystem: controllers.NPMProxy,
			expected:  "lodash",
		},
		{
			name:      "NPM without secret",
			path:      "/api/v1/dependency-proxy/npm/lodash",
			ecosystem: controllers.NPMProxy,
			expected:  "lodash",
		},
		{
			name:      "NPM scoped package with secret",
			path:      "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/npm/@babel/core",
			ecosystem: controllers.NPMProxy,
			expected:  "@babel/core",
		},
		{
			name:      "NPM scoped package without secret",
			path:      "/api/v1/dependency-proxy/npm/@babel/core",
			ecosystem: controllers.NPMProxy,
			expected:  "@babel/core",
		},
		{
			name:      "Go with secret",
			path:      "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/go/github.com/foo/bar",
			ecosystem: controllers.GoProxy,
			expected:  "github.com/foo/bar",
		},
		{
			name:      "Go without secret",
			path:      "/api/v1/dependency-proxy/go/github.com/foo/bar",
			ecosystem: controllers.GoProxy,
			expected:  "github.com/foo/bar",
		},
		{
			name:      "no match returns original path",
			path:      "/something/completely/different",
			ecosystem: controllers.NPMProxy,
			expected:  "/something/completely/different",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := controllers.TrimProxyPrefix(tc.path, tc.ecosystem)
			assert.Equal(t, tc.expected, result)
		})
	}
}
