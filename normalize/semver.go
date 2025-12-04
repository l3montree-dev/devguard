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
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

// normalizeVersionPart removes leading zeros from a version part.
func normalizeVersionPart(versionPart string) string {
	normalized, err := strconv.Atoi(versionPart)
	if err != nil {
		// In case of error (which should not happen with numeric parts), return original.
		return versionPart
	}
	return strconv.Itoa(normalized)
}

var (
	ErrInvalidVersion = fmt.Errorf("invalid version")
)

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

func SemverFix(version string) (string, error) {
	version = strings.TrimPrefix(version, "v")

	if version == "" || version == "0" {
		return "", ErrInvalidVersion
	}

	// remove anything after "~"
	if strings.Contains(version, "~") {
		version = strings.Split(version, "~")[0]
	}

	// lets check if we need to fix the semver - there are some cases where the semver is not valid
	// examples are: "1.5", "1.0", "19.03.9", "3.0-beta1"
	// we need to fix these to be valid semver
	if ValidSemverRegex.MatchString(version) {
		// If the version is already a valid semver, no need to fix.
		return version, nil
	}

	// Attempt to fix common semver issues.
	// Split version by ".", "-" to check for missing parts.
	parts := regexp.MustCompile(`[\.-]`).Split(version, -1)

	for i, part := range parts {
		if strings.HasPrefix(part, "0") && len(part) > 1 {
			// Remove leading zeros from version parts.
			parts[i] = normalizeVersionPart(part)
		}
	}

	// Reconstruct the version string with the fixed parts.
	fixedVersion := strings.Join(parts, ".")

	switch len(parts) {
	case 1: // Missing MINOR and PATCH version
		fixedVersion += ".0.0"
	case 2: // Missing PATCH version
		fixedVersion += ".0"
	case 3: // Possible that we have a pre-release without PATCH
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(parts[2]) {
			// The third part is not numeric, likely a pre-release without PATCH
			fixedVersion = fmt.Sprintf("%s.%s.0-%s", parts[0], parts[1], parts[2])
		}
	case 4: // Might have pre-release or build metadata directly after MINOR
		fixedVersion = fmt.Sprintf("%s.%s.0-%s+%s", parts[0], parts[1], parts[2], parts[3])
	}

	// Re-check if the fixed version is now valid.
	if ValidSemverRegex.MatchString(fixedVersion) {
		return fixedVersion, nil
	}

	// If we can't fix it to be a valid semver, return the original version.
	return version, ErrInvalidVersion
}
