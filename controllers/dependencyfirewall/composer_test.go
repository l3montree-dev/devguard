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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComposerEcosystem(t *testing.T) {
	t.Run("trimPrefix with and without secret", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "without secret",
				path:     "/api/v1/dependency-proxy/composer/p2/monolog/monolog.json",
				expected: "p2/monolog/monolog.json",
			},
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/composer/p2/monolog/monolog.json",
				expected: "p2/monolog/monolog.json",
			},
			{
				name:     "without trailing path",
				path:     "/api/v1/dependency-proxy/composer",
				expected: "",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.expected, composer.trimPrefix(tc.path))
			})
		}
	})

	t.Run("parsePackage", func(t *testing.T) {
		cases := []struct {
			name    string
			path    string
			pkg     string
			version string
		}{
			{
				name: "metadata",
				path: "p2/monolog/monolog.json",
				pkg:  "monolog/monolog",
			},
			{
				name: "dev metadata",
				path: "p2/monolog/monolog~dev.json",
				pkg:  "monolog/monolog",
			},
			{
				name: "metadata with leading slash",
				path: "/p2/monolog/monolog.json",
				pkg:  "monolog/monolog",
			},
			{
				name:    "dist",
				path:    "dist/monolog/monolog/3.5.0.zip",
				pkg:     "monolog/monolog",
				version: "3.5.0",
			},
			{
				name:    "dist with dev version",
				path:    "dist/monolog/monolog/dev-main.zip",
				pkg:     "monolog/monolog",
				version: "dev-main",
			},
			{
				name:    "dist with prerelease version",
				path:    "dist/symfony/console/6.4.0-beta1.zip",
				pkg:     "symfony/console",
				version: "6.4.0-beta1",
			},
			{
				name: "root packages file",
				path: "packages.json",
			},
			{
				name: "dist without vendor",
				path: "dist/foo.zip",
			},
			{
				name: "metadata without vendor",
				path: "p2/foo.json",
			},
			{
				name: "metadata with too many segments",
				path: "p2/a/b/c.json",
			},
			{
				name: "dist without version",
				path: "dist/monolog/monolog/.zip",
			},
			{
				name: "unknown prefix",
				path: "whatever/monolog/monolog.json",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pkg, version := composer.parsePackage(tc.path)
				assert.Equal(t, tc.pkg, pkg)
				assert.Equal(t, tc.version, version)
			})
		}
	})

	t.Run("packageIdentifier", func(t *testing.T) {
		assert.Equal(t, "pkg:composer/monolog/monolog@3.5.0", composer.packageIdentifier("monolog/monolog", "3.5.0"))
		assert.Equal(t, "pkg:composer/monolog/monolog", composer.packageIdentifier("monolog/monolog", ""))
	})
}
