package dependencyfirewall

import "testing"

func TestDebEcosystem(t *testing.T) {
	t.Run("trimPrefix with and without secret", func(t *testing.T) {
		cases := []struct {
			name     string
			path     string
			expected string
		}{
			{
				name:     "without secret",
				path:     "/api/v1/dependency-proxy/deb/debian/dists/trixie/InRelease",
				expected: "debian/dists/trixie/InRelease",
			},
			{
				name:     "with secret",
				path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/deb/debian/dists/trixie/InRelease",
				expected: "debian/dists/trixie/InRelease",
			},
			{
				name:     "url encoded version is decoded",
				path:     "/api/v1/dependency-proxy/deb/debian/pool/main/c/curl/curl_8.14.1-2%2bdeb13u5_arm64.deb",
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
				expectedName:    "curl",
				expectedVersion: "8.14.1-2+deb13u5",
			},
			{
				name:            "binary name differs from source name",
				path:            "debian/pool/main/k/krb5/libkrb5-3_1.21.3-5+deb13u1_arm64.deb",
				expectedName:    "libkrb5-3",
				expectedVersion: "1.21.3-5+deb13u1",
			},
			{
				name:            "architecture all",
				path:            "debian/pool/main/b/bash-completion/bash-completion_2.16.0-7_all.deb",
				expectedName:    "bash-completion",
				expectedVersion: "2.16.0-7",
			},
			{
				name:            "security repository with tilde",
				path:            "debian-security/pool/updates/main/o/openssl/openssl_3.5.7-1~deb13u3_arm64.deb",
				expectedName:    "openssl",
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
}
