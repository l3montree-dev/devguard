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
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
)

type sbomScanner struct {
	purlComparer comparer
}

// the vulnInPackage interface is used to abstract the different types of vulnerabilities
// it includes more than just the CVE ID to allow for more detailed information
// like the affected package version and fixed version

type comparer interface {
	GetVulns(purl packageurl.PackageURL) ([]models.VulnInPackage, error)
}

func NewSBOMScanner(purlComparer comparer, cveRepository shared.CveRepository) *sbomScanner {
	return &sbomScanner{
		purlComparer: purlComparer,
	}
}

func (s *sbomScanner) Scan(bom *normalize.SBOMGraph) ([]models.VulnInPackage, error) {
	errgroup := utils.ErrGroup[[]models.VulnInPackage](10)

	// iterate through all components
	for c := range bom.NodesOfType(normalize.GraphNodeTypeComponent) {
		component := c

		errgroup.Go(
			func() ([]models.VulnInPackage, error) {

				vulns := []models.VulnInPackage{}
				// if the component has no package url we cannot find anything
				if component.Component.PackageURL != "" {
					var res []models.VulnInPackage
					var err error

					parsed, err := packageurl.FromString(component.Component.PackageURL)
					if err != nil {
						slog.Warn("could not parse purl", "purl", component.Component.PackageURL, "err", err)
						return nil, err
					}

					res, err = s.purlComparer.GetVulns(parsed)
					if err != nil {
						slog.Warn("could not get cves", "purl", component.Component.PackageURL)
					}

					vulns = append(vulns, res...)
				}
				return vulns, nil
			})
	}

	vulns, err := errgroup.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	return utils.Flat(vulns), nil
}
