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
package normalize

import "testing"

func TestSemverFix(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver, err := SemverFix("")
		if err == nil {
			t.Errorf("Expected invalid version, got %s", semver)
		}
	})

	t.Run("v Prefix should be removed", func(t *testing.T) {
		semver, _ := SemverFix("v1.14.14")
		if semver != "1.14.14" {
			t.Errorf("Expected 1.14.14, got %s", semver)
		}
	})

	t.Run("valid semver", func(t *testing.T) {
		semver, _ := SemverFix("1.14.14")
		if semver != "1.14.14" {
			t.Errorf("Expected 1.14.14, got %s", semver)
		}
	})

	t.Run("invalid semver", func(t *testing.T) {
		// do a table driven test for the invalid semver
		invalidSemvers := []struct {
			input    string
			expected string
		}{
			{"1.14", "1.14.0"},
			{"1.0", "1.0.0"},
			{"19.03.9", "19.3.9"},
			{"3.0-beta1", "3.0.0-beta1"},
		}
		for _, tt := range invalidSemvers {
			semver, _ := SemverFix(tt.input)

			if semver != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, semver)
			}
		}
	})

	t.Run("test 2.4.27-10.sarge1.040815-1", func(t *testing.T) {
		semver, err := SemverFix("2.4.27-10.sarge1.040815-1")
		if err != nil {
			t.Errorf("Expected no error, got %s", err)
		}
		if semver != "2.4.27-10.sarge1.040815-1" {
			t.Errorf("Expected 2.4.27-10.sarge1.040815-1, got %s", semver)
		}

		t.Fatal(semver)
	})
}
