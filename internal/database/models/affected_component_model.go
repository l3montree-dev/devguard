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
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
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

/*
func combineAffectedComponentsUsingRanges(affectedComponents []AffectedComponent) []AffectedComponent {
	// get all the versions
	versions := make([]string, 0)
	for _, ac := range affectedComponents {
		if ac.Version == nil {
			return affectedComponents
		}
		versions = append(versions, *ac.Version)
	}

	// get the ranges
	ranges := versionsToRange(versions)

	// create the new affected components again
	newAffectedComponents := make([]AffectedComponent, len(ranges))
	for i, r := range ranges {
		if r[0] == r[1] {
			// create with version attribute
			cmp := affectedComponents[0]
			cmp.Version = &r[0]
			newAffectedComponents[i] = cmp
		} else {
			// create semver range component
			cmp := affectedComponents[0]
			cmp.Version = nil
			cmp.SemverIntroduced = &r[0]
			cmp.SemverFixed = &r[1]
			newAffectedComponents[i] = cmp
		}
	}

	return newAffectedComponents
}
*/

func AffectedComponentFromOSV(osv common.OSV) []AffectedComponent {
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
			if urgency, ok := affected.EcosystemSpecific["urgency"]; ok {
				if urgencyStr, ok := urgency.(string); ok {
					urgencyStr = strings.ToLower(urgencyStr)
					if urgencyStr == "unimportant" {
						// just continue
						continue
					}
				}
			}
		}

		if affected.Package.Purl != "" {

			purl, err := packageurl.FromString(affected.Package.Purl)
			if err != nil {
				slog.Debug("could not parse purl", "purl", affected.Package.Purl, "err", err)
				continue
			}
			qualifiersStr := purl.Qualifiers.String()

			// iterate over all ranges
			containsSemver := false
			for _, r := range affected.Ranges {
				if r.Type == "SEMVER" {
					containsSemver = true
				} else {
					continue
				}
				// iterate over all events
				for i, e := range r.Events {
					tmpE := e
					if i%2 != 0 {
						continue
					}

					// check if a fix does even exist
					fixed := ""
					if len(r.Events) != i+1 {
						// there is a fix available
						fixed = r.Events[i+1].Fixed
					}

					var semverIntroducedPtr *string
					var semverFixedPtr *string
					semverIntroduced, err := normalize.SemverFix(tmpE.Introduced)
					if err == nil {
						semverIntroducedPtr = &semverIntroduced
					}
					semverFixed, err := normalize.SemverFix(fixed)
					if err == nil {
						semverFixedPtr = &semverFixed
					}

					// create the affected package
					affectedComponent := AffectedComponent{
						PurlWithoutVersion: strings.Split(affected.Package.Purl, "?")[0],
						Ecosystem:          affected.Package.Ecosystem,
						Scheme:             "pkg",
						Type:               purl.Type,
						Name:               purl.Name,
						Namespace:          &purl.Namespace,
						Qualifiers:         &qualifiersStr,
						Subpath:            &purl.Subpath,

						Source: "osv",

						SemverIntroduced: semverIntroducedPtr,
						SemverFixed:      semverFixedPtr,

						CVE: cves,
					}
					affectedComponents = append(affectedComponents, affectedComponent)
				}
			}

			if !containsSemver {
				notSemverVersionedComponents := make([]AffectedComponent, 0, len(affected.Ranges))
				// create an affected package with a specific version
				for _, v := range affected.Versions {
					tmpV := v
					affectedComponent := AffectedComponent{
						PurlWithoutVersion: strings.Split(affected.Package.Purl, "?")[0],
						Ecosystem:          affected.Package.Ecosystem,
						Scheme:             "pkg",
						Type:               purl.Type,
						Name:               purl.Name,
						Namespace:          &purl.Namespace,
						Qualifiers:         &qualifiersStr,
						Subpath:            &purl.Subpath,
						Version:            &tmpV,

						Source: "osv",

						CVE: cves,
					}
					notSemverVersionedComponents = append(notSemverVersionedComponents, affectedComponent)
				}

				// combine the affected components using ranges - This adds a layer of heuristic to it.
				// affectedComponents = append(affectedComponents, combineAffectedComponentsUsingRanges(notSemverVersionedComponents)...)

				affectedComponents = append(affectedComponents, notSemverVersionedComponents...)
			}
		} else {
			for _, r := range affected.Ranges {
				if r.Type != "GIT" {
					continue
				}

				// repo: https://github.com/nextcloud/server
				repo := strings.TrimPrefix(r.Repo, "https://")

				name := strings.TrimPrefix(repo, "github.com/")
				name = strings.Trim(name, "/")

				purl := fmt.Sprintf("pkg:%s", repo)

				notPurlVersionedComponents := make([]AffectedComponent, 0, len(affected.Versions))
				for _, v := range affected.Versions {
					tmpV := v
					affectedComponent := AffectedComponent{
						PurlWithoutVersion: purl,
						Ecosystem:          affected.Package.Ecosystem,
						Scheme:             "pkg",
						Type:               "git",
						Name:               name,
						Version:            &tmpV,

						Source: "osv",

						CVE: cves,
					}
					notPurlVersionedComponents = append(notPurlVersionedComponents, affectedComponent)
				}
				affectedComponents = append(affectedComponents, notPurlVersionedComponents...)
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
		fixedVersion, err := normalize.SemverFix(v)
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
