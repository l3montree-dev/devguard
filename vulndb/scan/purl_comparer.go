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
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
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
func (comparer *PurlComparer) GetAffectedComponents(purl packageurl.PackageURL) ([]models.AffectedComponent, error) {
	ctx := normalize.ParsePurlForMatching(purl)

	if ctx.HowToInterpretVersionString == normalize.EmptyVersion {
		return []models.AffectedComponent{}, nil // No version = no results
	}

	var affectedComponents []models.AffectedComponent

	// Build the base query
	query := comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", ctx.SearchPurl)
	query = repositories.BuildQualifierQuery(query, ctx.Qualifiers, ctx.Namespace)

	// build the query
	query = repositories.BuildQueryBasedOnMatchContext(query, ctx)
	err := query.
		Preload("CVE").Preload("CVE.Exploits").Preload("CVE.Relationships").
		Find(&affectedComponents).Error
	if err != nil {
		slog.Error("error executing affected components query", "error", err)
		return nil, err
	}

	if ctx.HowToInterpretVersionString == normalize.EcosystemSpecificVersion {
		// Filter the results based on introduced/fixed versions or exact match
		affectedComponents = filterMatchingComponentsByVersion(affectedComponents, ctx.NormalizedVersion)
	}

	return affectedComponents, err
}

func (comparer *PurlComparer) GetVulns(purl packageurl.PackageURL) ([]models.VulnInPackage, error) {
	// get the affected components
	affectedComponents, err := comparer.GetAffectedComponents(purl)
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

func filterMatchingComponentsByVersion(components []models.AffectedComponent, lookingForVersion string) []models.AffectedComponent {
	matchingComponents := []models.AffectedComponent{}

	for _, component := range components {
		match, err := normalize.CheckVersion(component.Version, component.VersionIntroduced, component.VersionFixed, lookingForVersion, component.Type)
		if err != nil {
			slog.Warn("could not check version for affected component", "error", err, "lookingForVersion", lookingForVersion, "purl", component.PurlWithoutVersion, "introduced", utils.OrDefault(component.VersionIntroduced, "<nil>"), "fixed", utils.OrDefault(component.VersionFixed, "<nil>"))
			continue
		}
		if match {
			matchingComponents = append(matchingComponents, component)
		}
	}

	return matchingComponents
}
