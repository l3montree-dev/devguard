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

package main

import (
	"reflect"
	"testing"
)

func TestMapPackageManagerToEcosystem(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{"npm", "npm", "node"},
		{"yarn", "yarn", "node"},
		{"pnpm", "pnpm", "node"},
		{"pip", "pip", "python"},
		{"pipenv", "pipenv", "python"},
		{"poetry", "poetry", "python"},
		{"cargo", "cargo", "crates"},
		{"unknown", "maven", "unknown"},
		{"empty", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapPackageManagerToEcosystem(tt.pkg)
			if result != tt.expected {
				t.Errorf("mapPackageManagerToEcosystem(%q) = %q, want %q", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected [3]int
	}{
		{"standard version", "1.2.3", [3]int{1, 2, 3}},
		{"with pre-release", "1.2.3-rc.0", [3]int{1, 2, 3}},
		{"with build metadata", "1.2.3+build.123", [3]int{1, 2, 3}},
		{"with both", "1.2.3-alpha.1+build", [3]int{1, 2, 3}},
		{"major version only", "5.0.0", [3]int{5, 0, 0}},
		{"empty string", "", [3]int{0, 0, 0}},
		{"invalid format", "invalid", [3]int{0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVersion(tt.version)
			if result != tt.expected {
				t.Errorf("parseVersion(%q) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestParsePurl(t *testing.T) {
	tests := []struct {
		name         string
		purl         string
		expectedType string
		expectedName string
		expectedVer  string
		expectError  bool
	}{
		{
			name:         "simple npm package",
			purl:         "pkg:npm/express@4.18.2",
			expectedType: "npm",
			expectedName: "express",
			expectedVer:  "4.18.2",
			expectError:  false,
		},
		{
			name:         "scoped package",
			purl:         "pkg:npm/@sentry/nextjs@9.38.0",
			expectedType: "npm",
			expectedName: "@sentry/nextjs",
			expectedVer:  "9.38.0",
			expectError:  false,
		},
		{
			name:         "cargo package",
			purl:         "pkg:cargo/serde@1.0.0",
			expectedType: "cargo",
			expectedName: "serde",
			expectedVer:  "1.0.0",
			expectError:  false,
		},
		{
			name:         "package without version",
			purl:         "pkg:npm/react",
			expectedType: "npm",
			expectedName: "react",
			expectedVer:  "",
			expectError:  false,
		},
		{
			name:        "invalid purl",
			purl:        "invalid-purl",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgType, name, version, err := parsePurl(tt.purl)
			if tt.expectError {
				if err == nil {
					t.Errorf("parsePurl(%q) expected error but got none", tt.purl)
				}
			} else {
				if err != nil {
					t.Errorf("parsePurl(%q) unexpected error: %v", tt.purl, err)
				}
				if pkgType != tt.expectedType {
					t.Errorf("parsePurl(%q) type = %q, want %q", tt.purl, pkgType, tt.expectedType)
				}
				if name != tt.expectedName {
					t.Errorf("parsePurl(%q) name = %q, want %q", tt.purl, name, tt.expectedName)
				}
				if version != tt.expectedVer {
					t.Errorf("parsePurl(%q) version = %q, want %q", tt.purl, version, tt.expectedVer)
				}
			}
		})
	}
}

func TestParseVersionSpec(t *testing.T) {
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
			rangeType, version := parseVersionSpec(tt.spec)
			if rangeType != tt.expectedRangeType {
				t.Errorf("parseVersionSpec(%q) rangeType = %q, want %q", tt.spec, rangeType, tt.expectedRangeType)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseVersionSpec(%q) version = %q, want %q", tt.spec, version, tt.expectedVersion)
			}
		})
	}
}

func TestMatchesVersionSpec(t *testing.T) {
	tests := []struct {
		name         string
		rangeType    string
		version      string
		versionParts [3]int
		baseVersion  string
		baseParts    [3]int
		expected     bool
	}{
		// Caret tests (^)
		{"caret: same major, >= base", "^", "1.2.3", [3]int{1, 2, 3}, "1.0.0", [3]int{1, 0, 0}, true},
		{"caret: same major, < base", "^", "1.0.0", [3]int{1, 0, 0}, "1.2.3", [3]int{1, 2, 3}, false},
		{"caret: different major", "^", "2.0.0", [3]int{2, 0, 0}, "1.0.0", [3]int{1, 0, 0}, false},
		// Caret with 0-major versions (semver-correct behavior)
		{"caret: 0.Y.Z allows same minor", "^", "0.2.5", [3]int{0, 2, 5}, "0.2.3", [3]int{0, 2, 3}, true},
		{"caret: 0.Y.Z rejects different minor", "^", "0.3.0", [3]int{0, 3, 0}, "0.2.3", [3]int{0, 2, 3}, false},
		{"caret: 0.0.Z allows only same patch", "^", "0.0.3", [3]int{0, 0, 3}, "0.0.3", [3]int{0, 0, 3}, true},
		{"caret: 0.0.Z rejects different patch", "^", "0.0.4", [3]int{0, 0, 4}, "0.0.3", [3]int{0, 0, 3}, false},

		// Tilde tests (~)
		{"tilde: same major.minor, >= patch", "~", "1.2.5", [3]int{1, 2, 5}, "1.2.3", [3]int{1, 2, 3}, true},
		{"tilde: same major.minor, < patch", "~", "1.2.1", [3]int{1, 2, 1}, "1.2.3", [3]int{1, 2, 3}, false},
		{"tilde: different minor", "~", "1.3.0", [3]int{1, 3, 0}, "1.2.3", [3]int{1, 2, 3}, false},

		// Greater than or equal (>=)
		{">=: same major, >= base", ">=", "1.5.0", [3]int{1, 5, 0}, "1.0.0", [3]int{1, 0, 0}, true},
		{">=: different major", ">=", "2.0.0", [3]int{2, 0, 0}, "1.0.0", [3]int{1, 0, 0}, false},

		// Greater than (>)
		{"greater: same major, > base", ">", "1.5.0", [3]int{1, 5, 0}, "1.0.0", [3]int{1, 0, 0}, true},
		{"greater: same major, = base", ">", "1.0.0", [3]int{1, 0, 0}, "1.0.0", [3]int{1, 0, 0}, false},

		// Exact tests
		{"exact: matching", "exact", "1.2.3", [3]int{1, 2, 3}, "1.2.3", [3]int{1, 2, 3}, true},
		{"exact: not matching", "exact", "1.2.4", [3]int{1, 2, 4}, "1.2.3", [3]int{1, 2, 3}, false},

		// Invalid range type
		{"invalid range type", "invalid", "1.2.3", [3]int{1, 2, 3}, "1.2.3", [3]int{1, 2, 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesVersionSpec(tt.rangeType, tt.version, tt.versionParts, tt.baseVersion, tt.baseParts)
			if result != tt.expected {
				t.Errorf("matchesVersionSpec(%q, %q, ...) = %v, want %v", tt.rangeType, tt.version, result, tt.expected)
			}
		})
	}
}

func TestGetAllDependencyMaps(t *testing.T) {
	npmResp := &NPMResponse{
		Dependencies: map[string]string{
			"dep1": "1.0.0",
		},
		PeerDependencies: map[string]string{
			"peer1": "2.0.0",
		},
		OptionalDependencies: map[string]string{
			"opt1": "3.0.0",
		},
		DevDependencies: map[string]string{
			"dev1": "4.0.0",
		},
	}

	maps := getAllDependencyMaps(npmResp)

	if len(maps) != 4 {
		t.Errorf("getAllDependencyMaps() returned %d maps, want 4", len(maps))
	}

	if maps[0]["dep1"] != "1.0.0" {
		t.Error("Dependencies map not in expected position")
	}
	if maps[1]["peer1"] != "2.0.0" {
		t.Error("PeerDependencies map not in expected position")
	}
	if maps[2]["opt1"] != "3.0.0" {
		t.Error("OptionalDependencies map not in expected position")
	}
	if maps[3]["dev1"] != "4.0.0" {
		t.Error("DevDependencies map not in expected position")
	}
}

func TestFindDependencyVersionInMeta(t *testing.T) {
	npmResp := &NPMResponse{
		Dependencies: map[string]string{
			"express": "4.18.2",
		},
		DevDependencies: map[string]string{
			"jest": "29.0.0",
		},
		PeerDependencies: map[string]string{
			"react": "18.0.0",
		},
	}

	tests := []struct {
		name     string
		pkgName  string
		expected string
	}{
		{"found in dependencies", "express", "4.18.2"},
		{"found in devDependencies", "jest", "29.0.0"},
		{"found in peerDependencies", "react", "18.0.0"},
		{"not found", "nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findDependencyVersionInMeta(npmResp, tt.pkgName)
			if result != tt.expected {
				t.Errorf("findDependencyVersionInMeta(%q) = %q, want %q", tt.pkgName, result, tt.expected)
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

func TestGetRecommendedVersions(t *testing.T) {
	npmResp := NPMResponse{
		Versions: map[string]VersionData{
			"1.0.0":      {Version: "1.0.0"},
			"1.1.0":      {Version: "1.1.0"},
			"1.2.0":      {Version: "1.2.0"},
			"1.2.1":      {Version: "1.2.1"},
			"2.0.0":      {Version: "2.0.0"},
			"1.2.0-rc.0": {Version: "1.2.0-rc.0"},
		},
	}

	tests := []struct {
		name             string
		currentVersion   string
		expectedCount    int
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:             "from 1.0.0",
			currentVersion:   "1.0.0",
			expectedCount:    4,
			shouldContain:    []string{"1.0.0", "1.1.0", "1.2.0", "1.2.1"},
			shouldNotContain: []string{"2.0.0", "1.2.0-rc.0"},
		},
		{
			name:             "from 1.2.0",
			currentVersion:   "1.2.0",
			expectedCount:    2,
			shouldContain:    []string{"1.2.0", "1.2.1"},
			shouldNotContain: []string{"1.0.0", "1.1.0", "2.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getRecommendedVersions(npmResp, tt.currentVersion)
			if err != nil {
				t.Errorf("getRecommendedVersions() error = %v", err)
				return
			}

			if len(result) != tt.expectedCount {
				t.Errorf("getRecommendedVersions() returned %d versions, want %d", len(result), tt.expectedCount)
			}

			for _, shouldContain := range tt.shouldContain {
				found := false
				for _, v := range result {
					if v == shouldContain {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("getRecommendedVersions() missing %q in result", shouldContain)
				}
			}

			for _, shouldNotContain := range tt.shouldNotContain {
				for _, v := range result {
					if v == shouldNotContain {
						t.Errorf("getRecommendedVersions() should not contain %q", shouldNotContain)
					}
				}
			}
		})
	}
}

func TestResolveBestVersion(t *testing.T) {
	allVersionsMeta := &NPMResponse{
		Versions: map[string]VersionData{
			"1.0.0": {Version: "1.0.0"},
			"1.1.0": {Version: "1.1.0"},
			"1.2.0": {Version: "1.2.0"},
			"1.2.1": {Version: "1.2.1"},
			"2.0.0": {Version: "2.0.0"},
		},
	}

	tests := []struct {
		name           string
		versionSpec    string
		currentVersion string
		expected       string
		shouldError    bool
	}{
		{"exact version", "1.2.0", "1.0.0", "1.2.0", false},
		{"caret: highest in range", "^1.2.0", "1.0.0", "1.2.1", false},
		{"caret: no match default", "^3.0.0", "1.0.0", "", true},
		{"greater than or equal", ">=1.1.0", "1.0.0", "1.2.1", false},
		{"exact: same as current", "1.0.0", "1.0.0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveBestVersion(allVersionsMeta, tt.versionSpec, tt.currentVersion)
			if (err != nil) != tt.shouldError {
				t.Errorf("resolveBestVersion(%q, %q) error = %v, shouldError = %v", tt.versionSpec, tt.currentVersion, err, tt.shouldError)
				return
			}
			if !tt.shouldError && result != tt.expected {
				t.Errorf("resolveBestVersion(%q, %q) = %q, want %q", tt.versionSpec, tt.currentVersion, result, tt.expected)
			}
		})
	}
}

func TestResolveBestVersionWithOrExpression(t *testing.T) {
	allVersionsMeta := &NPMResponse{
		Versions: map[string]VersionData{
			"13.0.0": {Version: "13.0.0"},
			"14.0.0": {Version: "14.0.0"},
			"14.5.0": {Version: "14.5.0"},
			"15.0.0": {Version: "15.0.0"},
			"15.4.0": {Version: "15.4.0"},
		},
	}

	tests := []struct {
		name           string
		versionSpec    string
		currentVersion string
		expected       string
		shouldError    bool
	}{
		{"OR expression: match both, returns highest", "^14.0.0 || ^15.0.0", "13.0.0", "15.4.0", false},
		{"OR expression: match second", "^14.0.0 || ^15.4.0", "13.0.0", "15.4.0", false},
		{"OR expression: no match", "^16.0.0 || ^17.0.0", "13.0.0", "", true},
		{"OR expression: incomplete semver ^14.0", "^14.0 || ^15.0.0", "13.0.0", "15.4.0", false},
		{"OR expression: incomplete semver ^14", "^14 || ^15.0.0", "13.0.0", "15.4.0", false},
		{"OR expression: incomplete semver ^14.0 matches", "^14.0", "13.0.0", "14.5.0", false},
		{"OR expression: incomplete semver ^14 matches", "^14", "13.0.0", "14.5.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveBestVersion(allVersionsMeta, tt.versionSpec, tt.currentVersion)
			if (err != nil) != tt.shouldError {
				t.Errorf("resolveBestVersion(%q, %q) error = %v, shouldError = %v", tt.versionSpec, tt.currentVersion, err, tt.shouldError)
				return
			}
			if !tt.shouldError && result != tt.expected {
				t.Errorf("resolveBestVersion(%q, %q) = %q, want %q", tt.versionSpec, tt.currentVersion, result, tt.expected)
			}
		})
	}
}
