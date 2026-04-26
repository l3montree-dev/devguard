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

func TestNPMEcosystem(t *testing.T) {
	t.Run("trimPrefix with and without secret", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "without secret",
				path:     "/api/v1/dependency-proxy/npm/lodash",
				expected: "lodash",
			},
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/npm/@babel/core",
				expected: "@babel/core",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := npm.trimPrefix(tc.path); got != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, got)
				}
			})
		}
	})

	t.Run("parse metadata path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/lodash")
		if pkg != "lodash" || version != "" {
			t.Fatalf("expected lodash with empty version, got %q and %q", pkg, version)
		}
	})

	t.Run("parse tarball path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/lodash/-/lodash-4.17.21.tgz")
		if pkg != "lodash" || version != "4.17.21" {
			t.Fatalf("expected lodash@4.17.21, got %q@%q", pkg, version)
		}
	})

	t.Run("parse scoped tarball path", func(t *testing.T) {
		pkg, version := npm.parsePackage("/@babel/core/-/core-7.23.0.tgz")
		if pkg != "@babel/core" || version != "7.23.0" {
			t.Fatalf("expected @babel/core@7.23.0, got %q@%q", pkg, version)
		}
	})
}
