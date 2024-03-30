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

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type sbomScanner struct {
	cpeComparer  comparer
	purlComparer comparer
}

// the vulnInPackage interface is used to abstract the different types of vulnerabilities
// it includes more than just the CVE ID to allow for more detailed information
// like the affected package version and fixed version
type vulnInPackage struct {
	CVEID             string
	FixedVersion      *string
	IntroducedVersion *string
	PackageName       string
	PurlWithVersion   string
}

func (v vulnInPackage) GetIntroducedVersion() string {
	if v.IntroducedVersion != nil {
		return *v.IntroducedVersion
	}
	return ""
}

func (v vulnInPackage) GetFixedVersion() string {
	if v.FixedVersion != nil {
		return *v.FixedVersion
	}
	return ""
}

type comparer interface {
	GetVulns(packageIdentifier string) ([]vulnInPackage, error)
}

func NewSBOMScanner(cpeComparer comparer, purlComparer comparer) *sbomScanner {
	return &sbomScanner{
		cpeComparer:  cpeComparer,
		purlComparer: purlComparer,
	}
}

func (s *sbomScanner) Scan(bom *cdx.BOM) ([]vulnInPackage, error) {
	vulnerabilities := make([]vulnInPackage, 0)
	// iterate through all components
	for _, component := range *bom.Components {
		// check if CPE is present
		if component.CPE != "" {
			c, err := s.cpeComparer.GetVulns(component.CPE)
			if err != nil {
				slog.Warn("could not get cves", "err", err, "cpe", component.CPE)
				continue
			}
			vulnerabilities = append(vulnerabilities, c...)
		} else if component.PackageURL != "" {
			c, err := s.purlComparer.GetVulns(component.PackageURL)
			if err != nil {
				slog.Warn("could not get cves", "err", err, "purl", component.PackageURL)
				continue
			}
			vulnerabilities = append(vulnerabilities, c...)
		}
	}

	return vulnerabilities, nil
}
