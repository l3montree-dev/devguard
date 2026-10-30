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

func TestDebEcosystem(t *testing.T) {
	t.Run("trimPrefix", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/deb/debian/dists/trixie/InRelease",
				expected: "debian/dists/trixie/InRelease",
			},
			{
				name:     "url encoded version is decoded",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/deb/debian/pool/main/c/curl/curl_8.14.1-2%2bdeb13u5_arm64.deb",
				expected: "debian/pool/main/c/curl/curl_8.14.1-2+deb13u5_arm64.deb",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := deb.trimPrefix(tc.path); got != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, got)
				}
			})
		}
	})

	t.Run("parsePackage", func(t *testing.T) {
		cases := []struct {
			name            string
			path            string
			expectedName    string
			expectedVersion string
		}{
			{
				name:            "simple package",
				path:            "debian/pool/main/c/curl/curl_8.14.1-2+deb13u5_arm64.deb",
				expectedName:    "debian/curl",
				expectedVersion: "8.14.1-2+deb13u5",
			},
			{
				name:            "binary name differs from source name",
				path:            "debian/pool/main/k/krb5/libkrb5-3_1.21.3-5+deb13u1_arm64.deb",
				expectedName:    "debian/libkrb5-3",
				expectedVersion: "1.21.3-5+deb13u1",
			},
			{
				name:            "architecture all",
				path:            "debian/pool/main/b/bash-completion/bash-completion_2.16.0-7_all.deb",
				expectedName:    "debian/bash-completion",
				expectedVersion: "2.16.0-7",
			},
			{
				name:            "security repository with tilde",
				path:            "debian-security/pool/updates/main/o/openssl/openssl_3.5.7-1~deb13u3_arm64.deb",
				expectedName:    "debian/openssl",
				expectedVersion: "3.5.7-1~deb13u3",
			},
			{
				name: "InRelease",
				path: "debian/dists/trixie/InRelease",
			},
			{
				name: "Packages by hash",
				path: "debian/dists/trixie/main/binary-arm64/by-hash/SHA256/fe771d58d4af39dbb94142d6f3ce578d340c6b1364c172d9e87f2287bdc4994b",
			},
			{
				name: "deb file with too many underscores",
				path: "debian/pool/main/f/foo/foo_1.0_extra_arm64.deb",
			},
			{
				name: "deb file with too few underscores",
				path: "debian/pool/main/f/foo/foo_1.0.deb",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				name, version := deb.parsePackage(tc.path)
				if name != tc.expectedName || version != tc.expectedVersion {
					t.Fatalf("expected %q@%q, got %q@%q", tc.expectedName, tc.expectedVersion, name, version)
				}
			})
		}
	})

	t.Run("parseDebDistPath", func(t *testing.T) {
		cases := []struct {
			name            string
			path            string
			expectedArchive string
			expectedSuite   string
			expectedRest    string
			expectedOk      bool
		}{
			{
				name:            "InRelease",
				path:            "debian/dists/trixie/InRelease",
				expectedArchive: "debian",
				expectedSuite:   "trixie",
				expectedRest:    "InRelease",
				expectedOk:      true,
			},
			{
				name:            "security InRelease",
				path:            "debian-security/dists/trixie-security/InRelease",
				expectedArchive: "debian-security",
				expectedSuite:   "trixie-security",
				expectedRest:    "InRelease",
				expectedOk:      true,
			},
			{
				name:            "Packages index",
				path:            "debian/dists/trixie/main/binary-amd64/Packages.xz",
				expectedArchive: "debian",
				expectedSuite:   "trixie",
				expectedRest:    "main/binary-amd64/Packages.xz",
				expectedOk:      true,
			},
			{
				name: "deb file",
				path: "debian/pool/main/c/curl/curl_8.14.1-2_amd64.deb",
			},
			{
				name: "missing rest",
				path: "debian/dists/trixie",
			},
			{
				name: "missing archive",
				path: "/dists/trixie/InRelease",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				archive, suite, rest, ok := parseDebDistPath(tc.path)
				if archive != tc.expectedArchive || suite != tc.expectedSuite || rest != tc.expectedRest || ok != tc.expectedOk {
					t.Fatalf("expected %q %q %q %v, got %q %q %q %v", tc.expectedArchive, tc.expectedSuite, tc.expectedRest, tc.expectedOk, archive, suite, rest, ok)
				}
			})
		}
	})
}
