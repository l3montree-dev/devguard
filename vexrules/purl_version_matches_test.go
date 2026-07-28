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

package vexrules

import (
	"testing"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func mustPurl(t *testing.T, purl string) packageurl.PackageURL {
	t.Helper()
	p, err := packageurl.FromString(purl)
	assert.NoError(t, err)
	return p
}

func TestPurlVersionMatches(t *testing.T) {
	cases := []struct {
		name        string
		patternPurl string
		pathPurl    string
		want        bool
		wantErr     bool
	}{
		{
			name:        "matching type/namespace/name and version within constraint",
			patternPurl: "pkg:npm/lib@>=1.0.0,<2.0.0",
			pathPurl:    "pkg:npm/lib@1.5.0",
			want:        true,
		},
		{
			name:        "matching name but version outside constraint",
			patternPurl: "pkg:npm/lib@>=1.0.0,<2.0.0",
			pathPurl:    "pkg:npm/lib@2.0.0",
			want:        false,
		},
		{
			name:        "different name",
			patternPurl: "pkg:npm/lib@>=1.0.0,<2.0.0",
			pathPurl:    "pkg:npm/other@1.5.0",
			want:        false,
		},
		{
			name:        "different namespace",
			patternPurl: "pkg:golang/l3montree-dev/devguard@>=1.0.0",
			pathPurl:    "pkg:golang/someoneelse/devguard@1.5.0",
			want:        false,
		},
		{
			name:        "different type",
			patternPurl: "pkg:npm/lib@>=1.0.0",
			pathPurl:    "pkg:golang/lib@1.5.0",
			want:        false,
		},
		{
			name:        "exact version constraint match",
			patternPurl: "pkg:npm/lib@1.0.0",
			pathPurl:    "pkg:npm/lib@1.0.0",
			want:        true,
		},
		{
			name:        "invalid pattern version constraint",
			patternPurl: "pkg:npm/lib@not-a-constraint",
			pathPurl:    "pkg:npm/lib@1.0.0",
			wantErr:     true,
		},
		{
			name:        "invalid path version",
			patternPurl: "pkg:npm/lib@>=1.0.0",
			pathPurl:    "pkg:npm/lib@not-a-version",
			wantErr:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patternPurl := mustPurl(t, tc.patternPurl)
			pathPurl := mustPurl(t, tc.pathPurl)

			got, err := PurlVersionMatches(patternPurl, pathPurl)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
