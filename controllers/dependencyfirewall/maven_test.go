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

func TestMavenParsePackage(t *testing.T) {
	cases := []struct {
		name            string
		path            string
		expectedPkg     string
		expectedVersion string
	}{
		{
			name:            "jar artifact",
			path:            "/com/fake/artifact/1.2.3/artifact-1.2.3.jar",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3",
		},
		{
			name:            "pom artifact",
			path:            "/com/fake/artifact/1.2.3/artifact-1.2.3.pom",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3",
		},
		{
			name:            "artifact with classifier",
			path:            "/com/fake/artifact/1.2.3/artifact-1.2.3-sources.jar",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3",
		},
		{
			name:            "checksum file",
			path:            "/com/fake/artifact/1.2.3/artifact-1.2.3.jar.sha1",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3",
		},
		{
			name:            "known malicious package from osv",
			path:            "/org/mvnpm/posthog-node/4.18.1/posthog-node-4.18.1.jar",
			expectedPkg:     "org.mvnpm/posthog-node",
			expectedVersion: "4.18.1",
		},
		{
			name:            "deeply nested group id",
			path:            "/io/github/leetcrunch/scribejava-core/8.3.5/scribejava-core-8.3.5.jar",
			expectedPkg:     "io.github.leetcrunch/scribejava-core",
			expectedVersion: "8.3.5",
		},
		{
			name:            "artifact level metadata",
			path:            "/com/fake/artifact/maven-metadata.xml",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "",
		},
		{
			name:            "artifact level metadata checksum",
			path:            "/com/fake/artifact/maven-metadata.xml.sha1",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "",
		},
		{
			name:            "snapshot metadata inside version directory",
			path:            "/com/fake/artifact/1.2.3-SNAPSHOT/maven-metadata.xml",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3-SNAPSHOT",
		},
		{
			name:            "snapshot artifact with build timestamp",
			path:            "/com/fake/artifact/1.2.3-SNAPSHOT/artifact-1.2.3-20240101.120000-1.jar",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3-SNAPSHOT",
		},
		{
			name:            "path without leading slash",
			path:            "com/fake/artifact/1.2.3/artifact-1.2.3.jar",
			expectedPkg:     "com.fake/artifact",
			expectedVersion: "1.2.3",
		},
		{
			name:            "directory listing is not a package",
			path:            "/com/fake/artifact/",
			expectedPkg:     "",
			expectedVersion: "",
		},
		{
			name:            "root is not a package",
			path:            "/",
			expectedPkg:     "",
			expectedVersion: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, version := maven.parsePackage(tc.path)
			if pkg != tc.expectedPkg || version != tc.expectedVersion {
				t.Fatalf("expected %q@%q, got %q@%q", tc.expectedPkg, tc.expectedVersion, pkg, version)
			}
		})
	}
}

func TestMavenPackageIdentifier(t *testing.T) {
	if got := maven.packageIdentifier("org.mvnpm/posthog-node", "4.18.1"); got != "pkg:maven/org.mvnpm/posthog-node@4.18.1" {
		t.Fatalf("unexpected identifier with version: %q", got)
	}
	if got := maven.packageIdentifier("org.mvnpm/posthog-node", ""); got != "pkg:maven/org.mvnpm/posthog-node" {
		t.Fatalf("unexpected identifier without version: %q", got)
	}
}

func TestMavenEcosystemTrimPrefix(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "without secret",
			path:     "/api/v1/dependency-proxy/maven/com/fake/artifact/maven-metadata.xml",
			expected: "com/fake/artifact/maven-metadata.xml",
		},
		{
			name:     "with secret",
			path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/maven/com/fake/artifact/1.2.3/artifact-1.2.3.jar",
			expected: "com/fake/artifact/1.2.3/artifact-1.2.3.jar",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maven.trimPrefix(tc.path); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestMavenContentType(t *testing.T) {
	cases := map[string]string{
		"/com/fake/artifact/1.2.3/artifact-1.2.3.jar":      "application/java-archive",
		"/com/fake/artifact/1.2.3/artifact-1.2.3.pom":      "application/xml",
		"/com/fake/artifact/maven-metadata.xml":            "application/xml",
		"/com/fake/artifact/1.2.3/artifact-1.2.3.jar.sha1": "text/plain",
		"/com/fake/artifact/1.2.3/artifact-1.2.3.module":   "application/octet-stream",
	}

	for path, expected := range cases {
		t.Run(path, func(t *testing.T) {
			if got := mavenContentType(path); got != expected {
				t.Fatalf("expected %q, got %q", expected, got)
			}
		})
	}
}
