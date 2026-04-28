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

package dependencyfirewall

import "testing"

func TestPyPIParsePackage(t *testing.T) {
	t.Run("parses simple index path", func(t *testing.T) {
		pkg, version := pypi.parsePackage("/simple/requests/")
		if pkg != "requests" || version != "" {
			t.Fatalf("expected requests with empty version, got %q and %q", pkg, version)
		}
	})

	t.Run("parses package artifact path with leading slash", func(t *testing.T) {
		pkg, version := pypi.parsePackage("/packages/ab/cd/requests-2.31.0-py3-none-any.whl")
		if pkg != "requests" || version != "2.31.0" {
			t.Fatalf("expected requests@2.31.0, got %q@%q", pkg, version)
		}
	})
}

func TestPyPIEcosystemTrimPrefix(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "without secret",
			path:     "/api/v1/dependency-proxy/pypi/simple/requests/",
			expected: "simple/requests/",
		},
		{
			name:     "with secret",
			path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/pypi/simple/requests/",
			expected: "simple/requests/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pypi.trimPrefix(tc.path); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
