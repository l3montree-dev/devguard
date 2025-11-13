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
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
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

	// Step 2: Determine which version to use
	targetVersion := version
	if targetVersion == "" {
		targetVersion = parsedPurl.Version
		if targetVersion == "" {
			return []models.AffectedComponent{}, nil // No version = no results
		}
	}

	// Step 3: Try to normalize the version to semantic versioning format
	normalizedVersion, versionIsValid := normalize.SemverFix(targetVersion)

	// Step 4: Create search key (purl without version)
	parsedPurl.Version = ""
	searchPurl := parsedPurl.ToString()

	var affectedComponents []models.AffectedComponent

	if versionIsValid != nil {
		// Version isn't semantic versioning - do exact match only
		comparer.db.Model(&models.AffectedComponent{}).
			Where("purl = ? AND version = ?", searchPurl, targetVersion).
			Preload("CVE").Preload("CVE.Exploits").
			Find(&affectedComponents)
	} else {
		// Version is semantic versioning - check version ranges
		comparer.db.Model(&models.AffectedComponent{}).
			Where("purl = ?", searchPurl).
			Where(comparer.buildVersionRangeQuery(targetVersion, parsedPurl.Version, normalizedVersion)).
			Preload("CVE").Preload("CVE.Exploits").
			Find(&affectedComponents)
	}

	return affectedComponents, nil
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
