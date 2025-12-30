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
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestFromOSV(t *testing.T) {
	t.Run("empty OSV", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{},
		}
		affectedComponents := AffectedComponentFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package without purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Pkg{
						Purl: "",
					},
					Ranges: []dtos.Rng{},
				},
			},
		}
		affectedComponents := AffectedComponentFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with invalid purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Pkg{
						Purl: "invalidPURL",
					},
					Ranges: []dtos.Rng{},
				},
			},
		}
		affectedComponents := AffectedComponentFromOSV(osv)
		if len(affectedComponents) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with valid purl", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Rng{
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
		affectedComponents := AffectedComponentFromOSV(osv)
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
					Package: dtos.Pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Rng{
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

		affectedComponents := AffectedComponentFromOSV(osv)
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
					Package: dtos.Pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []dtos.Rng{
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

		affectedComponents := AffectedComponentFromOSV(osv)
		if len(affectedComponents) != 1 {
			t.Errorf("Expected 1 affected packages, got %d", len(affectedComponents))
		}
		assert.Equal(t, "1.14.14", *affectedComponents[0].SemverIntroduced)
		assert.Equal(t, "1.14.15", *affectedComponents[0].SemverFixed)
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

		affectedComponents := AffectedComponentFromOSV(osv)
		if len(affectedComponents) != 2 {
			t.Errorf("Expected 2 affected package, got %d", len(affectedComponents))
		}
	})

	t.Run("affected package with GIT ranges", func(t *testing.T) {
		osv := dtos.OSV{
			Affected: []dtos.Affected{
				{
					Package: dtos.Pkg{
						Purl: "pkg:github/package-url/purl-spec",
					},
					Ranges: []dtos.Rng{
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

		affectedComponents := AffectedComponentFromOSV(osv)
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

		affectedComponents := AffectedComponentFromOSV(osv)
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
			CVE: []CVE{
				{},
			},
		}
		affectedComponent.BeforeSave(nil) // nolint:errcheck

		otherAffectedComponent := AffectedComponent{
			PurlWithoutVersion: "pkg:golang/toolchain",
			Namespace:          ptr("golang"),
			CVE:                make([]CVE, 0),
		}

		otherAffectedComponent.BeforeSave(nil) // nolint:errcheck
		if affectedComponent.ID != otherAffectedComponent.ID {
			t.Errorf("Expected the same hash, got %s and %s", affectedComponent.ID, otherAffectedComponent.ID)
		}
	})
}

func TestAlpineCVE2021_3711(t *testing.T) {
	// read the file
	f, _ := os.Open("testdata/ALPINE-CVE-2021-3711.json")
	defer f.Close()
	bytes, _ := io.ReadAll(f)
	osv := dtos.OSV{}
	err := json.Unmarshal(bytes, &osv)
	if err != nil {
		t.Errorf("Could not unmarshal osv, got %s", err)
	}

	affectedComponents := AffectedComponentFromOSV(osv)

	// for simplicity just do assertions on the ecosystem Alpine:v3.11
	ac := utils.Filter(affectedComponents, func(el AffectedComponent) bool {
		return el.Ecosystem == "Alpine:v3.11"
	})
	assert.Equal(t, 18, len(ac))
	// validate the versions
	expected := []string{
		"1.1.1-r1",
		"1.1.1-r2",
		"1.1.1-r3",
		"1.1.1-r4",
		"1.1.1-r5",
		"1.1.1a-r0",
		"1.1.1a-r1",
		"1.1.1b-r0",
		"1.1.1b-r1",
		"1.1.1c-r0",
		"1.1.1c-r1",
		"1.1.1d-r1",
		"1.1.1d-r2",
		"1.1.1d-r3",
		"1.1.1g-r0",
		"1.1.1i-r0",
		"1.1.1j-r0",
		"1.1.1k-r0",
	}
	for i, acEntry := range ac {
		assert.Equal(t, expected[i], *acEntry.Version)
		assert.Nil(t, acEntry.SemverIntroduced)
		assert.Nil(t, acEntry.SemverFixed)
	}
}
