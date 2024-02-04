// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package vulndb

import (
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestFromOSV(t *testing.T) {
	t.Run("empty OSV", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{},
		}
		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedPackages))
		}
	})

	t.Run("affected package without purl", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{
				{
					Package: pkg{
						Purl: "",
					},
					Ranges: []rng{},
				},
			},
		}
		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedPackages))
		}
	})

	t.Run("affected package with invalid purl", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{
				{
					Package: pkg{
						Purl: "invalid_purl",
					},
					Ranges: []rng{},
				},
			},
		}
		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 0 {
			t.Errorf("Expected no affected packages, got %d", len(affectedPackages))
		}
	})

	t.Run("affected package with valid purl", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{
				{
					Package: pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []rng{
						{
							Type: "SEMVER",
							Events: []semverEvent{
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
		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 1 {
			t.Errorf("Expected 1 affected package, got %d", len(affectedPackages))
		}
		if affectedPackages[0].PURL != "pkg:golang/toolchain" {
			t.Errorf("Expected purl to be pkg:ecosystem/name@version, got %s", affectedPackages[0].PURL)
		}
		if affectedPackages[0].Ecosystem != "" {
			t.Errorf("Expected ecosystem to be ecosystem, got %s", affectedPackages[0].Ecosystem)
		}
		if affectedPackages[0].Scheme != "pkg" {
			t.Errorf("Expected scheme to be pkg, got %s", affectedPackages[0].Scheme)
		}
		if affectedPackages[0].Type != "golang" {
			t.Errorf("Expected type to be golang, got %s", affectedPackages[0].Type)
		}
		if affectedPackages[0].Name != "toolchain" {
			t.Errorf("Expected name to be toolchain, got %s", affectedPackages[0].Name)
		}
		if *affectedPackages[0].Namespace != "" {
			t.Errorf("Expected namespace to be '', got %s", *affectedPackages[0].Namespace)
		}
		if *affectedPackages[0].Qualifiers != "" {
			t.Errorf("Expected qualifiers to be '', got %s", *affectedPackages[0].Qualifiers)
		}

		// check the semver range
		if *affectedPackages[0].SemverIntroduced != "0" {
			t.Errorf("Expected semver introduced to be 0, got %s", *affectedPackages[0].SemverIntroduced)
		}

		if *affectedPackages[0].SemverFixed != "1.14.14" {
			t.Errorf("Expected semver fixed to be 1.14.14, got %s", *affectedPackages[0].SemverFixed)
		}

		// check the hash
		if affectedPackages[0].ID != "b1ab57d3763ceefa" {
			t.Errorf("Expected ID to be set, got %s", affectedPackages[0].ID)
		}
	})

	t.Run("affected package with multiple SEMVER ranges", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{
				{
					Package: pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []rng{
						{
							Type: "SEMVER",
							Events: []semverEvent{
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

		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 2 {
			t.Errorf("Expected 2 affected packages, got %d", len(affectedPackages))
		}

		// check if both affected ranges are present
		if *affectedPackages[0].SemverIntroduced != "0" {
			t.Errorf("Expected semver introduced to be 0, got %s", *affectedPackages[0].SemverIntroduced)
		}

		if *affectedPackages[0].SemverFixed != "1.14.14" {
			t.Errorf("Expected semver fixed to be 1.14.14, got %s", *affectedPackages[0].SemverFixed)
		}

		if *affectedPackages[1].SemverIntroduced != "1.14.15" {
			t.Errorf("Expected semver introduced to be 1.14.15, got %s", *affectedPackages[1].SemverIntroduced)
		}

		if *affectedPackages[1].SemverFixed != "1.15.0" {
			t.Errorf("Expected semver fixed to be 1.15.0, got %s", *affectedPackages[1].SemverFixed)
		}
	})

	t.Run("affected package without SEMVER ranges but with versions", func(t *testing.T) {
		osv := OSV{
			Affected: []affected{
				{
					Package: pkg{
						Purl: "pkg:golang/toolchain",
					},
					Ranges: []rng{
						{
							Type: "ECOSYSTEM",
							Events: []semverEvent{
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

		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 2 {
			t.Errorf("Expected 2 affected packages, got %d", len(affectedPackages))
		}

		// check if both affected versions are present
		if *affectedPackages[0].Version != "1.14.14" {
			t.Errorf("Expected version to be 1.14.14, got %s", *affectedPackages[0].Version)
		}

		if *affectedPackages[1].Version != "1.14.15" {
			t.Errorf("Expected version to be 1.14.15, got %s", *affectedPackages[1].Version)
		}
	})

	t.Run("try GHSA-2v6x-frw8-7r7f.json", func(t *testing.T) {
		// read the file
		f, _ := os.Open("testdata/GHSA-2v6x-frw8-7r7f.json")
		defer f.Close()
		bytes, _ := io.ReadAll(f)
		osv := OSV{}
		err := json.Unmarshal(bytes, &osv)
		if err != nil {
			t.Errorf("Could not unmarshal osv, got %s", err)
		}

		affectedPackages := fromOSV(osv)
		if len(affectedPackages) != 2 {
			t.Errorf("Expected 2 affected package, got %d", len(affectedPackages))
		}
	})
}
