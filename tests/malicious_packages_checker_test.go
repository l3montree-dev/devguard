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
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
)

// TestMaliciousPackageChecker tests the malicious package detection
func TestMaliciousPackageChecker(t *testing.T) {
	t.Parallel()
	// Set up test database
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	// Create repository
	maliciousPackageRepository := repositories.NewMaliciousPackageRepository(db)

	// Create a test malicious package entry
	testEntry := dtos.OSV{
		ID:      "MAL-TEST-001",
		Summary: "Test malicious package",
		Details: "This is a test entry for malicious package detection",
		Affected: []dtos.Affected{
			{
				Package: dtos.Package{
					Ecosystem: "npm",
					Name:      "fake-malicious-npm-package",
					Purl:      "pkg:npm/fake-malicious-npm-package",
				},
				Versions: []string{"1.0.0", "1.0.1"},
			},
		},
		Published: time.Now(),
		Modified:  time.Now(),
	}

	// Insert test data directly via GORM
	pkg := models.MaliciousPackage{
		ID:        testEntry.ID,
		Summary:   testEntry.Summary,
		Details:   testEntry.Details,
		Published: testEntry.Published,
		Modified:  testEntry.Modified,
	}
	err := db.Create(&pkg).Error
	assert.Nil(t, err)

	components := transformer.MaliciousAffectedComponentFromOSV(&testEntry, testEntry.ID)
	err = db.Create(&components).Error
	assert.Nil(t, err)

	// Create the checker
	checker, err := vulndb.NewMaliciousPackageChecker(maliciousPackageRepository)
	if err != nil {
		t.Fatalf("Failed to create malicious package checker: %v", err)
	}

	tests := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		expected  bool
		error     bool
	}{
		{
			name:      "Malicious package with specific version",
			ecosystem: "npm",
			pkgName:   "fake-malicious-npm-package",
			version:   "1.0.0",
			expected:  true,
		},
		{
			name:      "Malicious package with another version",
			ecosystem: "npm",
			pkgName:   "fake-malicious-npm-package",
			version:   "1.0.1",
			expected:  true,
		},
		{
			name:      "Malicious package without version",
			ecosystem: "npm",
			pkgName:   "fake-malicious-npm-package",
			version:   "",
			expected:  false,
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
			pkgName:   "fake-malicious-npm-package",
			version:   "1.0.0",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			components, err := checker.GetMaliciousComponents(context.Background(), tt.ecosystem, tt.pkgName)
			if tt.error {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)

			isMalicious := false
			for _, comp := range components {
				if comp.AffectsAllVersions() || vulndb.MatchesVersion(comp, tt.version) {
					isMalicious = true
					break
				}
			}

			if isMalicious != tt.expected {
				t.Errorf("malicious check (%s, %s, %s) = %v, want %v",
					tt.ecosystem, tt.pkgName, tt.version, isMalicious, tt.expected)
			}
		})
	}
}
