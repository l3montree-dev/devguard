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
