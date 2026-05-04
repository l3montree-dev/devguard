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

func TestGoEcosystem(t *testing.T) {
	t.Run("trimPrefix with and without secret", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "without secret",
				path:     "/api/v1/dependency-proxy/go/github.com/foo/bar",
				expected: "github.com/foo/bar",
			},
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/go/github.com/foo/bar",
				expected: "github.com/foo/bar",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := golang.trimPrefix(tc.path); got != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, got)
				}
			})
		}
	})

	t.Run("parse explicit version info path", func(t *testing.T) {
		pkg, version := golang.parsePackage("/github.com/foo/bar@v/v1.2.3.info")
		if pkg != "github.com/foo/bar" || version != "v1.2.3" {
			t.Fatalf("expected github.com/foo/bar@v1.2.3, got %q@%q", pkg, version)
		}
	})

	t.Run("parse list path returns empty version", func(t *testing.T) {
		pkg, version := golang.parsePackage("/github.com/foo/bar@v/list")
		if pkg != "github.com/foo/bar" || version != "" {
			t.Fatalf("expected github.com/foo/bar with empty version, got %q@%q", pkg, version)
		}
	})
}
