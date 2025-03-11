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
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type sbomScanner struct {
	cpeComparer  comparer
	purlComparer comparer
}

// the vulnInPackage interface is used to abstract the different types of vulnerabilities
// it includes more than just the CVE ID to allow for more detailed information
// like the affected package version and fixed version

type comparer interface {
	GetVulns(purl string, notASemverVersion string, componentType string) ([]models.VulnInPackage, error)
}

func NewSBOMScanner(cpeComparer comparer, purlComparer comparer, cveRepository core.CveRepository) *sbomScanner {
	return &sbomScanner{
		cpeComparer:  cpeComparer,
		purlComparer: purlComparer,
	}
}

func (s *sbomScanner) Scan(bom normalize.SBOM) ([]models.VulnInPackage, error) {
	errgroup := utils.ErrGroup[[]models.VulnInPackage](10)

	// iterate through all components
	for _, c := range *bom.GetComponents() {
		component := c

		errgroup.Go(
			func() ([]models.VulnInPackage, error) {
				// check if CPE is present
				vulns := []models.VulnInPackage{}
				if component.CPE != "" {
					res, err := s.cpeComparer.GetVulns(component.CPE, component.Version, string(component.Type))
					if err != nil {
						slog.Warn("could not get cves", "err", err, "cpe", component.CPE)
						return nil, nil
					}
					vulns = append(vulns, res...)
				}
				if component.PackageURL != "" {
					var res []models.VulnInPackage
					var err error
					/*if component.Type == cyclonedx.ComponentTypeApplication {
						// try to convert the purl to a CPE
						res, err = s.cpeComparer.GetVulns(component.PackageURL, component.Version, string(component.Type))
						if err != nil {
							slog.Warn("could not get cves", "err", err, "purl", component.PackageURL)
						} else {
							vulns = append(vulns, res...)
						}
					}*/
					res, err = s.purlComparer.GetVulns(component.PackageURL, component.Version, string(component.Type))
					if err != nil {
						slog.Warn("could not get cves", "err", err, "purl", component.PackageURL)
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
