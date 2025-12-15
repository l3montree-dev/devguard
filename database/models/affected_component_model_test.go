// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package models

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

func TestFromOSV(t *testing.T) {
	t.Run("empty OSV", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{},
		}
		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package without purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "",
					},
					Ranges: []dtos.Range{},
				},
			},
		}
		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with invalid purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "invalidPURL",
					},
					Ranges: []dtos.Range{},
				},
			},
		}
		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with valid purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Range{
						{
							Type: "SEMVER",
							Events: []dtos.SemverEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "1.14.14",
								},
							},
						},
					},
				},
			},
		}
		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 1 {
			t.Errorf("Expected 1 affected package, got %d", len(affectedComponents))
		}
		if affectedComponents[0].PurlWithoutVersion != "pkg:golang/toolchain" {
			t.Errorf("Expected purl to be pkg:ecosystem/name@version, got %s", affectedComponents[0].PurlWithoutVersion)
		}
		if affectedComponents[0].Ecosystem != "" {
			t.Errorf("Expected ecosystem to be ecosystem, got %s", affectedComponents[0].Ecosystem)
		}
		if affectedComponents[0].Scheme != "pkg" {
			t.Errorf("Expected scheme to be pkg, got %s", affectedComponents[0].Scheme)
		}
		if affectedComponents[0].Type != "golang" {
			t.Errorf("Expected type to be golang, got %s", affectedComponents[0].Type)
		}
		if affectedComponents[0].Name != "toolchain" {
			t.Errorf("Expected name to be toolchain, got %s", affectedComponents[0].Name)
		}
		if *affectedComponents[0].Namespace != "" {
			t.Errorf("Expected namespace to be '', got %s", *affectedComponents[0].Namespace)
		}
		if *affectedComponents[0].Qualifiers != "" {
			t.Errorf("Expected qualifiers to be '', got %s", *affectedComponents[0].Qualifiers)
		}

		// check the semver range
		if *affectedComponents[0].SemverIntroduced != "0.0.0" {
			t.Errorf("Expected semver introduced to be 0.0.0, got %s", *affectedComponents[0].SemverIntroduced)
		}

		if *affectedComponents[0].SemverFixed != "1.14.14" {
			t.Errorf("Expected semver fixed to be 1.14.14, got %s", *affectedComponents[0].SemverFixed)
		}

		// check the hash
		affectedComponents[0].BeforeSave(nil) // nolint:errcheck

		if affectedComponents[0].ID != "a60faf290cdd4b70" { // nolint:all
			t.Errorf("Expected ID to be set, got %s", affectedComponents[0].ID)
		}
	})

	t.Run("affected package with multiple SEMVER ranges", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Range{
						{
							Type: "SEMVER",
							Events: []dtos.SemverEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "1.14.14",
								},
								{
									Introduced: "1.14.15",
								},
								{
									Fixed: "1.15.0",
								},
							},
						},
					},
				},
			},
		}

		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 2 {
			t.Errorf("Expected 2 affected packages, got %d", len(affectedComponents))
		}

		// check if both affected ranges are present
		if *affectedComponents[0].SemverIntroduced != "0.0.0" {
			t.Errorf("Expected semver introduced to be 0, got %s", *affectedComponents[0].SemverIntroduced)
		}

		if *affectedComponents[0].SemverFixed != "1.14.14" {
			t.Errorf("Expected semver fixed to be 1.14.14, got %s", *affectedComponents[0].SemverFixed)
		}

		if *affectedComponents[1].SemverIntroduced != "1.14.15" {
			t.Errorf("Expected semver introduced to be 1.14.15, got %s", *affectedComponents[1].SemverIntroduced)
		}

		if *affectedComponents[1].SemverFixed != "1.15.0" {
			t.Errorf("Expected semver fixed to be 1.15.0, got %s", *affectedComponents[1].SemverFixed)
		}
	})

	t.Run("affected package without SEMVER ranges but with versions", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Range{
						{
							Type: "ECOSYSTEM",
							Events: []dtos.SemverEvent{
								{
									Introduced: "1.14.14",
								},
								{
									Fixed: "1.14.15",
								},
							},
						},
					},
					Versions: []string{
						"1.14.14",
						"1.14.15",
					},
				},
			},
		}

		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 2 {
			t.Errorf("Expected 1 affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("try GHSA-2v6x-frw8-7r7f.json", func(t *testing.T) {
		// read the file
		f, _ := os.Open("testdata/GHSA-2v6x-frw8-7r7f.json")
		defer f.Close()
		bytes, _ := io.ReadAll(f)
		osv := dtos.OSV{}
		err := json.Unmarshal(bytes, &osv)
		if err != nil {
			t.Errorf("Could not unmarshal osv, got %s", err)
		}

		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 2 {
			t.Errorf("Expected 2 affected package, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with GIT ranges", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Purl: "pkg:github/package-url/purl-spec",
					},
					Ranges: []dtos.Range{
						{
							Type: "GIT",
							Events: []dtos.SemverEvent{
								{
									Introduced: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
								},
								{
									Fixed: "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
								},
							},
						},
					},
					Versions: []string{
						"1.14.14",
						"1.14.15",
					},
				},
			},
		}

		affectedComponents := AffectedComponentsFromOSV(osv)
		if len(affectedComponents) != 2 {
			t.Errorf("Expected 2 affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("try CVE-2024-52523", func(t *testing.T) {
		// read the file
		f, _ := os.Open("testdata/CVE-2024-52523.json")
		defer f.Close()
		bytes, _ := io.ReadAll(f)
		osv := dtos.OSV{}
		err := json.Unmarshal(bytes, &osv)
		if err != nil {
			t.Errorf("Could not unmarshal osv, got %s", err)
		}

		affectedComponents := AffectedComponentsFromOSV(osv)
		for _, ac := range affectedComponents {
			assert.Equal(t, "pkg:github.com/nextcloud/server", ac.PurlWithoutVersion)
			assert.Equal(t, ac.Type, "github.com")
			assert.Equal(t, ac.Name, "server")
			assert.Equal(t, *ac.Namespace, "nextcloud")
			assert.Nil(t, ac.SemverIntroduced)
			assert.Nil(t, ac.SemverFixed)
			assert.Nil(t, ac.VersionIntroduced)
			assert.Nil(t, ac.VersionFixed)
		}
	})
}

func ptr[T any](t T) *T {
	return &t
}

func TestSetIdHash(t *testing.T) {
	t.Run("should always set the same hash for the same input, even if cves get updated", func(t *testing.T) {
		affectedComponent := AffectedComponent{
			PurlWithoutVersion: "pkg:golang/toolchain",
			Namespace:          ptr("golang"),
			CVEs: []CVE{
				{},
			},
		}
		affectedComponent.BeforeSave(nil) // nolint:errcheck

		otherAffectedComponent := AffectedComponent{
			PurlWithoutVersion: "pkg:golang/toolchain",
			Namespace:          ptr("golang"),
			CVEs:               make([]CVE, 0),
		}

		otherAffectedComponent.BeforeSave(nil) // nolint:errcheck
		if affectedComponent.ID != otherAffectedComponent.ID {
			t.Errorf("Expected the same hash, got %s and %s", affectedComponent.ID, otherAffectedComponent.ID)
		}
	})
}

func TestVersionsToRange(t *testing.T) {
	t.Run("Test patch updates", func(t *testing.T) {
		versions := []string{
			"0.24.0",
			"0.24.1",
			"0.24.2",
		}

		expected := [][2]string{
			{"0.24.0", "0.24.2"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})

	t.Run("Test minor updates", func(t *testing.T) {
		versions := []string{
			"1.0.0",
			"1.1.0",
			"1.2.0",
		}

		expected := [][2]string{
			{"1.0.0", "1.2.0"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})

	t.Run("Test major updates should NEVER be in a range", func(t *testing.T) {
		versions := []string{
			"1.0.0",
			"2.0.0",
			"3.0.0",
		}

		expected := [][2]string{
			{"1.0.0", "1.0.0"},
			{"2.0.0", "2.0.0"},
			{"3.0.0", "3.0.0"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})

	t.Run("Test prerelease updates", func(t *testing.T) {
		versions := []string{
			"1.0.0-beta1",
			"1.0.0-beta2",
			"1.0.0-beta3",
		}

		expected := [][2]string{
			{"1.0.0-beta1", "1.0.0-beta3"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})

	t.Run("Test prerelease updates with patch updates", func(t *testing.T) {
		versions := []string{
			"1.0.0-beta1",
			"1.0.0-beta2",
			"1.0.0-beta3",
			"1.0.0",
			"1.0.1",
			"1.0.2",
		}

		expected := [][2]string{
			{"1.0.0-beta1", "1.0.2"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})

	t.Run("test different patch and prerelease versions", func(t *testing.T) {
		versions := []string{
			"1.0.0-beta1",
			"1.0.1-beta2",
			"1.0.2",
		}

		expected := [][2]string{
			{"1.0.0-beta1", "1.0.0-beta1"},
			{"1.0.1-beta2", "1.0.1-beta2"},
			{"1.0.2", "1.0.2"},
		}

		actual := versionsToRange(versions)

		if len(actual) != len(expected) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}

		for i, v := range actual {
			if v != expected[i] {
				t.Fatalf("Expected %v, got %v", expected, actual)
			}
		}
	})
}
