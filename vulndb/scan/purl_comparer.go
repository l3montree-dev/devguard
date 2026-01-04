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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
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
	ctx, err := normalize.ParsePurlForMatching(purl, version)
	if err != nil {
		return nil, errors.Wrap(err, "invalid package URL")
	}

	if ctx.EmptyVersion {
		return []models.AffectedComponent{}, nil // No version = no results
	}

	var affectedComponents []models.AffectedComponent

	// Build the base query
	query := comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", ctx.SearchPurl)
	query = repositories.BuildQualifierQuery(query, ctx.Qualifiers, ctx.Namespace)

	if ctx.VersionIsValid != nil {
		// Version isn't semantic versioning - do exact match only
		err = query.Where("version = ?", ctx.TargetVersion).
			Preload("CVE").Preload("CVE.Exploits").
			Find(&affectedComponents).Error
	} else {
		// Version is semantic versioning - check version ranges
		query = repositories.BuildVersionRangeQuery(query, ctx.TargetVersion, ctx.NormalizedVersion)
		err = query.Preload("CVE").Preload("CVE.Exploits").Find(&affectedComponents).Error
	}

	return affectedComponents, err
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
