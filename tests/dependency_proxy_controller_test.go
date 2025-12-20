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
	config := controllers.DependencyProxyConfig{
		CacheDir: tempDir,
	}

	// Create a malicious checker (can be nil for these tests)
	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)
	defer checker.Stop()

	controller := controllers.NewDependencyProxyController(config, checker)

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

	config := controllers.DependencyProxyConfig{
		CacheDir: tempDir,
	}

	checker, err := vulndb.NewMaliciousPackageChecker(nil)
	require.NoError(t, err)
	defer checker.Stop()

	controller := controllers.NewDependencyProxyController(config, checker)

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
