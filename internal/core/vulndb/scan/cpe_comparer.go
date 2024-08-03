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
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type cpeComparer struct {
	db core.DB
}

func NewCPEComparer(db core.DB) *cpeComparer {
	return &cpeComparer{
		db: db,
	}
}

func (c *cpeComparer) GetVulns(purl string) ([]models.VulnInPackage, error) {
	// convert the purl to a cpe
	cpe, err := utils.PurlToCPE(purl)
	if err != nil {
		return nil, err
	}

	// parse the cpe
	// split the criteria into its parts
	parts := strings.Split(cpe, ":")
	part := parts[2]
	vendor := parts[3]
	product := parts[4]
	version := parts[5]

	cpeMatches := []models.CPEMatch{}

	c.db.Model(models.CPEMatch{}).Where("(part = ? OR part = '*') AND (vendor = ? OR vendor = '*') AND (product = ? OR product = '*') AND (version = ? OR version = '*') AND (version_end_including >= ? OR version_end_including = '') AND (version_start_including <= ? OR version_start_including = '')", part, vendor, product, version, version, version).Preload("CVEs").Find(&cpeMatches)

	vulns := []models.VulnInPackage{}
	for _, cpeMatch := range cpeMatches {
		tmp := cpeMatch
		for _, cve := range cpeMatch.CVEs {
			vulns = append(vulns, models.VulnInPackage{
				CVEID:             cve.CVE,
				Purl:              purl,
				FixedVersion:      &tmp.VersionEndIncluding,
				IntroducedVersion: &tmp.VersionStartIncluding,
				InstalledVersion:  version,
				CVE:               *cve,
				PackageName:       purl,
			})
		}
	}
	return vulns, nil
}
