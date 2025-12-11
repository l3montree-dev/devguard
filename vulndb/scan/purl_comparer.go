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

package scan

import (
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

type PurlComparer struct {
	db shared.DB
}

func NewPurlComparer(db shared.DB) *PurlComparer {
	return &PurlComparer{
		db: db,
	}
}

// GetAffectedComponents finds security vulnerabilities for a software package
func (comparer *PurlComparer) GetAffectedComponents(purl, version string) ([]models.AffectedComponent, error) {
	// Step 1: Parse the package URL (purl)
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		return nil, errors.Wrap(err, "invalid package URL")
	}

	qualifier := parsedPurl.Qualifiers

	// Step 2: Determine which version to use
	targetVersion := version
	if targetVersion == "" {
		targetVersion = parsedPurl.Version
		if targetVersion == "" {
			return []models.AffectedComponent{}, nil // No version = no results
		}
	}

	// Step 3: Try to normalize the version to semantic versioning format
	normalizedVersion, versionIsValid := normalize.ConvertToSemver(targetVersion)

	// Step 4: Create search key (purl without version)
	parsedPurl.Version = ""
	parsedPurl.Qualifiers = nil
	searchPurl := parsedPurl.ToString()

	var affectedComponents []models.AffectedComponent

	// Build the qualifier query
	qualifierQuery := comparer.buildQualifierQuery(qualifier, parsedPurl.Namespace)

	if versionIsValid != nil {
		// Version isn't semantic versioning - do exact match only
		comparer.db.Model(&models.AffectedComponent{}).
			Where("purl = ? AND version = ?", searchPurl, targetVersion).
			Where(qualifierQuery).
			Preload("CVE").Preload("CVE.Exploits").
			Find(&affectedComponents)
	} else {
		// Version is semantic versioning - check version ranges
		comparer.db.Model(&models.AffectedComponent{}).
			Where("purl = ?", searchPurl).
			Where(comparer.buildVersionRangeQuery(targetVersion, parsedPurl.Version, normalizedVersion)).
			Where(qualifierQuery).
			Preload("CVE").Preload("CVE.Exploits").
			Find(&affectedComponents)
	}

	return affectedComponents, nil
}
func (comparer *PurlComparer) buildQualifierQuery(qualifiers packageurl.Qualifiers, namespace string) *gorm.DB {
	query := comparer.db

	for _, qualifier := range qualifiers {
		if qualifier.Key != "distro" {
			continue
		}
		distro := qualifier.Value
		// Capitalize the first letter of each word in the distro string (e.g., "debian-13.2" -> "Debian-13.2")
		distro = cases.Title(language.English).String(distro)

		switch namespace {
		case "debian":

			// Parse distro string (e.g., "debian-13.2" -> "Debian:13")
			// Split by '-' to get distribution name and version
			parts := strings.Split(distro, "-")
			if len(parts) >= 2 {
				distroName := parts[0]
				majorVersion := strings.Split(parts[1], ".")[0]     // Get major version (13.2 -> 13)
				ecosystemPattern := distroName + ":" + majorVersion // "Debian:13"

				query = query.Where("ecosystem LIKE ?", ecosystemPattern+"%")
			}
		case "alpine":
			// Only major and minor versions are used from the distro qualifier.
			// Example: "pkg:apk/alpine/curl@8.14.1-r2?arch=aarch64&distro=3.22.2" -> "Alpine:v3.22"
			parts := strings.Split(distro, ".")
			majorVersion := ""
			minorVersion := ""
			if len(parts) == 1 {
				// Alpine version only has major version
				majorVersion = parts[0] // Get major version (3 -> 3)
			} else if len(parts) >= 2 {
				majorVersion = parts[0] // Get major version (3.22.2 -> 3)
				minorVersion = parts[1] // Get minor version (3.22.2 -> 22)
			}
			ecosystemPattern := "Alpine:v" + majorVersion
			if minorVersion != "" {
				ecosystemPattern += "." + minorVersion
			}

			query = query.Where("ecosystem LIKE ?", ecosystemPattern+"%")
		default:
			return query
		}
	}

	return query
}

// buildVersionRangeQuery creates the database query for version range matching
func (comparer *PurlComparer) buildVersionRangeQuery(targetVersion, originalVersion, normalizedVersion string) *gorm.DB {
	return comparer.db.Where("version = ?", targetVersion). // Exact match - to the target version
								Or("version = ?", originalVersion).                                                     // Original purl version match
								Or("semver_introduced IS NULL AND semver_fixed > ?", normalizedVersion).                // Vulnerable from start until fixed version
								Or("semver_introduced <= ? AND semver_fixed IS NULL", normalizedVersion).               // Vulnerable from introduced version onwards
								Or("semver_introduced <= ? AND semver_fixed > ?", normalizedVersion, normalizedVersion) // Vulnerable in range
}

// some purls do contain versions, which cannot be found in the database. An example is git.
// the purl looks like: pkg:deb/debian/git@v2.30.2-1, while the version we would like it to match is: 1:2.30.2-1 ("1:" prefix)
func (comparer *PurlComparer) GetVulns(purl string, version string, _ string) ([]models.VulnInPackage, error) {
	// get the affected components
	affectedComponents, err := comparer.GetAffectedComponents(purl, version)
	if err != nil {
		return nil, errors.Wrap(err, "could not get affected components")
	}

	vulnerabilities := []models.VulnInPackage{}

	// transform the affected packages to the vulnInPackage struct
	for _, affectedComponent := range affectedComponents {
		for _, cve := range affectedComponent.CVE {
			fixed := affectedComponent.SemverFixed
			if fixed == nil {
				fixed = affectedComponent.VersionFixed
			}

			// append the cve to the vulnerabilities
			vulnerabilities = append(vulnerabilities, models.VulnInPackage{
				CVEID:        cve.CVE,
				Purl:         purl,
				CVE:          cve,
				FixedVersion: fixed,
			})
		}
	}

	return vulnerabilities, nil
}
