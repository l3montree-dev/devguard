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
	"io"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
)

type SBOMScanner struct {
	cpeComparer  Comparer
	purlComparer Comparer
}

type Comparer interface {
	GetCVEs(packageIdentifier string) ([]vulndb.CVE, error)
}

func NewSBOMScanner(cpeComparer Comparer, purlComparer Comparer) *SBOMScanner {
	return &SBOMScanner{
		cpeComparer:  cpeComparer,
		purlComparer: purlComparer,
	}
}

func (s *SBOMScanner) Scan(reader io.Reader) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}

	cves := make([]vulndb.CVE, 0)
	// iterate through all components
	for _, component := range *bom.Components {
		// check if CPE is present
		if component.CPE != "" {
			c, err := s.cpeComparer.GetCVEs(component.CPE)
			if err != nil {
				return err
			}
			cves = append(cves, c...)
		} else if component.PackageURL != "" {
			c, err := s.purlComparer.GetCVEs(component.PackageURL)
			if err != nil {
				slog.Info("could not get cves", "err", err)
				continue
			}
			cves = append(cves, c...)
		}
	}

	// print all found CVEs
	for _, cve := range cves {
		fmt.Println(cve.CVE)
	}

	return nil
}
