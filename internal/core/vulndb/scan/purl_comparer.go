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

package scan

import (
	"fmt"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type purlComparer struct {
	db core.DB
}

func NewPurlComparer(db core.DB) *purlComparer {
	return &purlComparer{
		db: db,
	}
}

// some purls do contain versions, which cannot be found in the database. An example is git.
// the purl looks like: pkg:deb/debian/git@v2.30.2-1, while the version we would like it to match is: 1:2.30.2-1 ("1:" prefix)
func (comparer *purlComparer) GetVulns(purl string, version string, _ string) ([]models.VulnInPackage, error) {
	// parse the purl
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse purl")
	}

	debug := false

	/*if strings.Contains(purl, "debian/git") {
		fmt.Println("purl", purl)
		fmt.Println(version)
		debug = true
	}*/

	affectedComponents := []models.AffectedComponent{}
	semVer, err := normalize.SemverFix(version)
	p.Version = "" // we save the purl without any version inside the database.
	if err != nil {
		// we use the fake semver version - if we can convert it.
		// this just allows best effort ordering
		comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", p.ToString()).Where("version = ?", version).Preload("CVE").Preload("CVE.Exploits").Find(&affectedComponents)
	} else {
		if debug {
			fmt.Println("semver", semVer, version)
		}

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

	vulnerabilities := []models.VulnInPackage{}

	// transform the affected packages to the vulnInPackage struct
	for _, affectedComponent := range affectedComponents {
		for _, cve := range affectedComponent.CVE {
			fixedVersion := affectedComponent.VersionFixed
			if fixedVersion == nil {
				fixedVersion = affectedComponent.SemverFixed
			}

			// append the cve to the vulnerabilities
			vulnerabilities = append(vulnerabilities, models.VulnInPackage{
				CVEID:             cve.CVE,
				FixedVersion:      fixedVersion,
				IntroducedVersion: affectedComponent.SemverIntroduced,
				PackageName:       affectedComponent.PURL,
				Purl:              purl,
				CVE:               cve,
				InstalledVersion:  version,
			})
		}
	}

	return vulnerabilities, nil
}
