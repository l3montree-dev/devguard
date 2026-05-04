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

package fixedversion

import (
	"reflect"
	"testing"

	"github.com/package-url/packageurl-go"
)

func TestNPMParseVersionConstraint(t *testing.T) {

	resolver := &NPMResolver{}
	tests := []struct {
		name              string
		spec              string
		expectedRangeType string
		expectedVersion   string
	}{
		{"caret range", "^1.2.3", "^", "1.2.3"},
		{"caret with pre-release", "^1.2.3-rc.0", "^", "1.2.3"},
		{"tilde range", "~1.2.3", "~", "1.2.3"},
		{"greater than or equal", ">=1.2.3", ">=", "1.2.3"},
		{"greater than", ">1.2.3", ">", "1.2.3"},
		{"exact version", "1.2.3", "exact", "1.2.3"},
		{"exact with pre-release", "1.2.3-alpha", "exact", "1.2.3"},
		{"with whitespace", "  ^  1.2.3  ", "^", "1.2.3"},
		{"caret with build metadata", "^1.2.3+build", "^", "1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rangeType, version := resolver.ParseVersionConstraint(tt.spec)
			if rangeType != tt.expectedRangeType {
				t.Errorf("parseVersionConstraint(%q) rangeType = %q, want %q", tt.spec, rangeType, tt.expectedRangeType)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseVersionConstraint(%q) version = %q, want %q", tt.spec, version, tt.expectedVersion)
			}
		})
	}
}

func TestMatchesVersionConstraint(t *testing.T) {
	tests := []struct {
		name        string
		rangeType   string
		version     string
		baseVersion string
		expected    bool
	}{
		// Caret tests (^)
		{"caret: same major, >= base", "^", "1.2.3", "1.0.0", true},
		{"caret: same major, < base", "^", "1.0.0", "1.2.3", false},
		{"caret: different major", "^", "2.0.0", "1.0.0", false},
		// Caret with 0-major versions (semver-correct behavior)
		{"caret: 0.Y.Z allows same minor", "^", "0.2.5", "0.2.3", true},
		{"caret: 0.Y.Z rejects different minor", "^", "0.3.0", "0.2.3", false},
		{"caret: 0.0.Z allows only same patch", "^", "0.0.3", "0.0.3", true},
		{"caret: 0.0.Z rejects different patch", "^", "0.0.4", "0.0.3", false},

		// Tilde tests (~)
		{"tilde: same major.minor, >= patch", "~", "1.2.5", "1.2.3", true},
		{"tilde: same major.minor, < patch", "~", "1.2.1", "1.2.3", false},
		{"tilde: different minor", "~", "1.3.0", "1.2.3", false},

		// Greater than or equal (>=)
		{">=: same major, >= base", ">=", "1.5.0", "1.0.0", true},
		{">=: different major", ">=", "2.0.0", "1.0.0", true},

		// Greater than (>)
		{"greater: same major, > base", ">", "1.5.0", "1.0.0", true},
		{"greater: same major, = base", ">", "1.0.0", "1.0.0", false},

		// Exact tests
		{"exact: matching", "exact", "1.2.3", "1.2.3", true},
		{"exact: not matching", "exact", "1.2.4", "1.2.3", false},

		// Invalid range type
		{"invalid range type", "invalid", "1.2.3", "1.2.3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesVersionConstraint(tt.rangeType, tt.version, tt.baseVersion)
			if result != tt.expected {
				t.Errorf("matchesVersionConstraint(%q, %q, %q) = %v, want %v", tt.rangeType, tt.version, tt.baseVersion, result, tt.expected)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"full semver", "14.0.0", "14.0.0"},
		{"missing patch", "14.0", "14.0.0"},
		{"missing minor and patch", "14", "14.0.0"},
		{"with pre-release", "14.0.0-rc.0", "14.0.0"},
		{"incomplete with pre-release", "14.0-rc.0", "14.0.0"},
		{"single version with pre-release", "14-rc.0", "14.0.0"},
		{"with build metadata", "14.0.0+build", "14.0.0"},
		{"incomplete with build metadata", "14.0+build", "14.0.0"},
		{"with whitespace", "  14.0  ", "14.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeVersion(tt.version)
			if result != tt.expected {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.version, result, tt.expected)
			}
		})
	}
}

func TestSplitOrExpression(t *testing.T) {
	tests := []struct {
		name        string
		versionSpec string
		expected    []string
	}{
		{
			name:        "simple OR",
			versionSpec: "^14.0.0 || ^15.0.0",
			expected:    []string{"^14.0.0", "^15.0.0"},
		},
		{
			name:        "three parts",
			versionSpec: "^13.0.0 || ^14.0.0 || ^15.0.0",
			expected:    []string{"^13.0.0", "^14.0.0", "^15.0.0"},
		},
		{
			name:        "no OR",
			versionSpec: "^15.0.0",
			expected:    []string{"^15.0.0"},
		},
		{
			name:        "with extra spaces",
			versionSpec: "  ^14.0.0  ||  ^15.0.0  ",
			expected:    []string{"^14.0.0", "^15.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitOrExpression(tt.versionSpec)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("splitOrExpression(%q) = %v, want %v", tt.versionSpec, result, tt.expected)
			}
		})
	}
}

func TestNPMRegistryURLConstruction(t *testing.T) {
	tests := []struct {
		name     string
		purlStr  string
		version  string
		expected string
	}{
		{"unscoped", "pkg:npm/express@4.18.2", "4.18.2", "https://registry.npmjs.org/express/4.18.2"},
		{"scoped", "pkg:npm/@babel/core@7.20.0", "7.20.0", "https://registry.npmjs.org/@babel/core/7.20.0"},
		{"scoped sentry", "pkg:npm/@sentry/nextjs@9.38.0", "9.38.0", "https://registry.npmjs.org/@sentry/nextjs/9.38.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, _ := packageurl.FromString(tt.purlStr)
			fullName := buildFullPackageName(purl)
			url := "https://registry.npmjs.org/" + fullName + "/" + tt.version
			if url != tt.expected {
				t.Errorf("registry URL = %q, want %q", url, tt.expected)
			}
		})
	}
}
