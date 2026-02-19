// Copyright 2026 larshermges
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		expectedName string
		expectedVer  string
		expectError  bool
	}{
		{
			name:         "simple package",
			purl:         "pkg:npm/express@4.18.2",
			expectedName: "express",
			expectedVer:  "4.18.2",
			expectError:  false,
		},
		{
			name:         "scoped package",
			purl:         "pkg:npm/@sentry/nextjs@9.38.0",
			expectedName: "@sentry/nextjs",
			expectedVer:  "9.38.0",
			expectError:  false,
		},
		{
			name:         "package without version",
			purl:         "pkg:npm/react",
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
			name, version, err := parsePurl(tt.purl)
			if tt.expectError {
				if err == nil {
					t.Errorf("parsePurl(%q) expected error but got none", tt.purl)
				}
			} else {
				if err != nil {
					t.Errorf("parsePurl(%q) unexpected error: %v", tt.purl, err)
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
