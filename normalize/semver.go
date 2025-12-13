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
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

func FixFixedVersion(purl string, fixedVersion *string) *string {
	if fixedVersion == nil || *fixedVersion == "" {
		return nil
	}

	// split the purl after the @ to get the version
	versionSubstrings := strings.SplitN(purl, "@", 2)
	if len(versionSubstrings) < 2 {
		return fixedVersion // no version in purl, return the fixed version as is
	}

	// check if ver starts with a v
	if strings.HasPrefix(versionSubstrings[1], "v") {
		v := ("v" + *fixedVersion)
		return &v
	}

	return fixedVersion
}

// Regex for validating a correct semver.
var ValidSemverRegex = regexp.MustCompile(`^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

func SemverSort(versions []string) {
	slices.SortStableFunc(versions, func(a, b string) int {
		return SemverCompare(a, b)
	})
}

func SemverCompare(v1, v2 string) int {
	// check if "v" prefix is present, if not add it for comparison
	if !strings.HasPrefix(v1, "v") {
		v1 = "v" + v1
	}
	if !strings.HasPrefix(v2, "v") {
		v2 = "v" + v2
	}

	return semver.Compare(v1, v2)
}
