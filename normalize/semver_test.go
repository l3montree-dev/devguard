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
package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSemverFix(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver, err := ConvertToSemver("")
		assert.NoError(t, err)
		assert.Equal(t, "", semver)
	})

	t.Run("v Prefix should be removed", func(t *testing.T) {
		semver, _ := ConvertToSemver("v1.14.14")
		if semver != "1.14.14" {
			t.Errorf("Expected 1.14.14, got %s", semver)
		}
	})

	t.Run("valid semver", func(t *testing.T) {
		semver, _ := ConvertToSemver("1.14.14")
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
			{"19.03.9", "19.03.9"},
			{"3.0-beta1", "3.0.0-beta1"},
		}
		for _, tt := range invalidSemvers {
			semver, _ := ConvertToSemver(tt.input)

			if semver != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, semver)
			}
		}
	})

	t.Run("test 2.4.27-10.sarge1.040815-1", func(t *testing.T) {
		semver, err := ConvertToSemver("2.4.27-10.sarge1.040815-1")
		if err != nil {
			t.Errorf("Expected no error, got %s", err)
		}
		if semver != "2.4.27-10.sarge1.040815-1" {
			t.Errorf("Expected 2.4.27-10.sarge1.040815-1, got %s", semver)
		}
	})
}

func TestFixFixedVersion(t *testing.T) {
	tests := []struct {
		name         string
		purl         string
		fixedVersion *string
		want         *string
	}{
		{
			name:         "nil fixedVersion returns nil",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1",
			fixedVersion: nil,
			want:         nil,
		},
		{
			name:         "empty fixedVersion returns nil",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1",
			fixedVersion: ptr(""),
			want:         nil,
		},
		{
			name:         "purl without @ returns fixedVersion",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim",
			fixedVersion: ptr("1.2.3"),
			want:         ptr("1.2.3"),
		},
		{
			name:         "version after @ does not start with v, returns fixedVersion",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1",
			fixedVersion: ptr("1.2.3"),
			want:         ptr("1.2.3"),
		},
		{
			name:         "version after @ starts with v, returns fixedVersion+ver",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim@v1.9.1",
			fixedVersion: ptr("1.2.3"),
			want:         ptr("v1.2.3"),
		},
		{
			name:         "version after @ is just v, returns fixedVersion+ver",
			purl:         "pkg:maven/org.apache.xmlgraphics/batik-anim@v",
			fixedVersion: ptr("1.2.3"),
			want:         ptr("v1.2.3"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FixFixedVersion(tt.purl, tt.fixedVersion)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}
