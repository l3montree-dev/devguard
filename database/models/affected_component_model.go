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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"

	"gorm.io/gorm"
)

type AffectedComponent struct {
	ID                 string `json:"id" gorm:"primaryKey;"`
	Source             string
	PurlWithoutVersion string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string  `json:"ecosystem" gorm:"type:text;"`
	Scheme             string  `json:"scheme" gorm:"type:text;"`
	Type               string  `json:"type" gorm:"type:text;"`
	Name               string  `json:"name" gorm:"type:text;"`
	Namespace          *string `json:"namespace" gorm:"type:text;"`
	Qualifiers         *string `json:"qualifiers" gorm:"type:text;"`
	Subpath            *string `json:"subpath" gorm:"type:text;"`
	Version            *string `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced   *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed        *string `json:"semverEnd" gorm:"type:semver;index"`

	VersionIntroduced *string `json:"versionIntroduced" gorm:"index"` // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering
	VersionFixed      *string `json:"versionFixed" gorm:"index"`      // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (affectedComponent AffectedComponent) TableName() string {
	return "affected_components"
}

func (affectedComponent AffectedComponent) CalculateHash() string {
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s",
		affectedComponent.PurlWithoutVersion,
		affectedComponent.Ecosystem,
		affectedComponent.Name,
		utils.SafeDereference(affectedComponent.Namespace),
		utils.SafeDereference(affectedComponent.Qualifiers),
		utils.SafeDereference(affectedComponent.Subpath),
		utils.SafeDereference(affectedComponent.Version),
		utils.SafeDereference(affectedComponent.SemverIntroduced),
		utils.SafeDereference(affectedComponent.SemverFixed),
		utils.SafeDereference(affectedComponent.VersionIntroduced),
		utils.SafeDereference(affectedComponent.VersionFixed),
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])[:16]
}

func (affectedComponent *AffectedComponent) BeforeSave(tx *gorm.DB) error {
	if affectedComponent.ID == "" {
		affectedComponent.ID = affectedComponent.CalculateHash()
	}
	return nil
}

func AffectedComponentFromOSV(osv dtos.OSV) []AffectedComponent {
	affectedComponents := make([]AffectedComponent, 0)

	cveIds := osv.GetCVE()
	cves := make([]CVE, len(cveIds))
	for i, cveID := range cveIds {
		cves[i] = CVE{CVE: cveID}
	}

	for _, affected := range osv.Affected {
		// check if the affected package has a purl
		if affected.EcosystemSpecific != nil {
			// get the urgency - debian defines it: https://security-team.debian.org/security_tracker.html#severity-levels
			if affected.EcosystemSpecific.Urgency == "unimportant" {
				// just continue
				continue
			}
		}

		if affected.Package.Purl != "" {
			// Use the shared helper function with ecosystem conversion enabled
			bases := affectedComponentBaseFromAffected(affected)
			for _, base := range bases {
				affectedComponent := AffectedComponent{
					ID:                 "",
					Source:             "osv",
					PurlWithoutVersion: base.PurlWithoutVersion,
					Ecosystem:          base.Ecosystem,
					Scheme:             base.Scheme,
					Type:               base.Type,
					Name:               base.Name,
					Namespace:          base.Namespace,
					Qualifiers:         base.Qualifiers,
					Subpath:            base.Subpath,
					Version:            base.Version,
					SemverIntroduced:   base.SemverIntroduced,
					SemverFixed:        base.SemverFixed,
					VersionIntroduced:  base.VersionIntroduced,
					VersionFixed:       base.VersionFixed,
					CVE:                cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		} else {
			// Handle GIT ranges (no purl case)
			bases := affectedComponentBaseFromGitRange(affected)
			for _, base := range bases {
				affectedComponent := AffectedComponent{
					ID:                 "",
					Source:             "osv",
					PurlWithoutVersion: base.PurlWithoutVersion,
					Ecosystem:          base.Ecosystem,
					Scheme:             base.Scheme,
					Type:               base.Type,
					Name:               base.Name,
					Version:            base.Version,
					Namespace:          base.Namespace,
					SemverIntroduced:   base.SemverIntroduced,
					SemverFixed:        base.SemverFixed,
					VersionIntroduced:  base.VersionIntroduced,
					VersionFixed:       base.VersionFixed,
					CVE:                cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}
	}
	return affectedComponents
}

func versionsToRange(versions []string) [][2]string {
	if len(versions) == 0 {
		return [][2]string{}
	}

	// try to fix all versions - if we cannot fix using semver - we cant do anything
	semvers := make([]string, 0)
	for _, v := range versions {
		fixedVersion, err := normalize.ConvertToSemver(v)
		if err != nil {
			continue
		}
		semvers = append(semvers, fixedVersion)
	}

	// now we only have semver versions
	// sort the semvers
	normalize.SemverSort(semvers)

	// lets check if we can create a range
	// split the semver in each part using a regex
	// and then compare the parts
	var startVersion string
	var cursor string
	cursorMatches := make([]string, 5)
	ranges := make([][2]string, 0)
	for _, v := range semvers {
		if startVersion == "" {
			startVersion = v
			cursor = v
			cursorMatches = normalize.ValidSemverRegex.FindStringSubmatch(v)
			continue
		}
		matches := normalize.ValidSemverRegex.FindStringSubmatch(v)

		// Extract the parts using indices
		major := matches[1]
		minor := matches[2]
		patch := matches[3]
		prerelease := matches[4] // Can be empty if not present
		// buildMetadata := matches[5] // Can be empty if not present

		if safeStringToInt(major) == safeStringToInt(cursorMatches[1])+1 {
			// the major version is different
			// we NEVER want to expand a range over a major version
			ranges = append(ranges, [2]string{startVersion, cursor})
			startVersion = v
			cursor = v
			cursorMatches = matches
			continue
		}

		// major versions are the same
		// maybe minor changed a bit
		if safeStringToInt(minor) == safeStringToInt(cursorMatches[2])+1 {
			// minor changed +1
			if patch == "0" {
				// patch is 0 - we can update the cursor
				cursor = v
				cursorMatches = matches
				continue
			}

			// patch is not 0 - we cannot further expand it
			ranges = append(ranges, [2]string{startVersion, cursor})
			startVersion = v
			cursor = v
			cursorMatches = matches
			continue
		}

		// minor versions are the same
		// maybe patch changed a bit
		if safeStringToInt(patch) == safeStringToInt(cursorMatches[3])+1 {
			// patch changed +1
			// check if prerelease was empty
			if cursorMatches[4] == "" {
				// this is enough for now: TODO Check if this heuristic holds
				cursor = v
				cursorMatches = matches
				continue
			}
			// prerelease wasnt empty - thus we expected a full release
			// no further expansion possible
			ranges = append(ranges, [2]string{startVersion, cursor})
			startVersion = v
			cursor = v
			cursorMatches = matches
			continue
		}

		// if prerelease is empty now - this is the next version
		if cursorMatches[4] != "" && prerelease == "" {
			// it is the next version - this is enough right now
			cursor = v
			cursorMatches = matches
			continue
		}

		// check if the "next prerelease version"
		diffA, diffB := stringDiff(prerelease, cursorMatches[4])
		// remove all "non" number character (a lot should already be done by stringDiff)
		prereleaseA := removeNonNumberChars(diffA)
		prereleaseB := removeNonNumberChars(diffB)

		// check if the prerelease is the next version
		if prereleaseA == prereleaseB+1 {
			// it is the next version - this is enough right now
			cursor = v
			cursorMatches = matches
			continue
		}

		// thats it - we cannot expand the range a range
		ranges = append(ranges, [2]string{startVersion, cursor})
		startVersion = v
		cursor = v
		cursorMatches = matches
	}

	// collect the last range
	ranges = append(ranges, [2]string{startVersion, cursor})

	return ranges
}

func removeNonNumberChars(s string) int {
	// remove all non number characters
	// we can do this by iterating over the string
	// and checking if the character is a number
	// if it is not a number we remove it
	// we can do this by creating a new string
	// and appending the character if it is a number
	// and then returning the new string
	newString := ""
	for i := range s {
		if s[i] >= '0' && s[i] <= '9' {
			newString += string(s[i])
		}
	}
	return safeStringToInt(newString)
}

func stringDiff(a, b string) (string, string) {
	onlyA := ""
	onlyB := ""

	for i := range a {
		if i >= len(b) {
			onlyA += string(a[i])
			continue
		}

		if a[i] != b[i] {
			onlyA += string(a[i])
			onlyB += string(b[i])
		}
	}

	// maybe there is a difference in length
	if len(a) > len(b) {
		onlyA += a[len(b):]
	} else if len(b) > len(a) {
		onlyB += b[len(a):]
	}

	return onlyA, onlyB
}

func safeStringToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return -math.MaxInt64
	}
	return i
}
