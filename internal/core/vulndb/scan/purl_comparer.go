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
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type PurlComparer struct {
	db core.DB
}

func NewPurlComparer(db core.DB) *PurlComparer {
	return &PurlComparer{
		db: db,
	}
}

// if version is an empty string, the version provided by the purl gets used.
// if that is an empty string as well - an error gets returned
func (comparer *PurlComparer) GetAffectedComponents(purl, version string) ([]models.AffectedComponent, error) {
	// parse the purl
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse purl")
	}

	affectedComponents := []models.AffectedComponent{}

	var semVer string
	if version == "" {
		semVer, err = normalize.SemverFix(p.Version)
		if err != nil {
			// we cannot find anything without a version
			return []models.AffectedComponent{}, nil
		}
		version = semVer
	} else {
		semVer, err = normalize.SemverFix(version)
	}

	// reset the purl version - the affected components are not version specific - instead range specific - not part of the purl
	p.Version = ""
	if err != nil {
		// will be not null if the version is not a semver version
		// we use the fake semver version - if we can convert it.
		// this just allows best effort ordering
		comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", p.ToString()).Where("version = ?", version).Preload("CVE").Preload("CVE.Exploits").Find(&affectedComponents)
	} else {
		// we can use the version from the purl todo a semver range check
		// check if the package is present in the database
		comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", p.ToString()).Where(
			comparer.db.Where(
				"version = ?", version).
				Or("semver_introduced IS NULL AND semver_fixed > ?", semVer).
				Or("semver_introduced < ? AND semver_fixed IS NULL", semVer).
				Or("semver_introduced < ? AND semver_fixed > ?", semVer, semVer),
		).Preload("CVE").Preload("CVE.Exploits").Find(&affectedComponents)
	}
	return affectedComponents, nil
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
