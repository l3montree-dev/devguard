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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/vulndb"
)

// TestMaliciousPackageChecker tests the malicious package detection
func TestMaliciousPackageChecker(t *testing.T) {
	// Create a temporary directory for test data
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "osv", "malicious")
	maliciousDir := filepath.Join(dbPath, "npm", "test-malicious-package")
	if err := os.MkdirAll(maliciousDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create a test malicious package entry
	testEntry := vulndb.MaliciousPackageEntry{
		ID:      "MAL-TEST-001",
		Summary: "Test malicious package",
		Details: "This is a test entry for malicious package detection",
		Affected: []vulndb.Affected{
			{
				Package: vulndb.Package{
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

	// Create the checker with SkipInitialUpdate to prevent downloading from GitHub
	checker, err := vulndb.NewMaliciousPackageChecker(vulndb.MaliciousPackageCheckerConfig{
		DBPath:            dbPath,
		UpdateInterval:    24 * time.Hour, // Long interval for tests
		SkipInitialUpdate: true,           // Skip GitHub download, use test data
	})
	if err != nil {
		t.Fatalf("Failed to create malicious package checker: %v", err)
	}
	defer checker.Stop()

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
