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
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"golang.org/x/mod/semver"
)

type cpeComparer struct {
	db core.DB
}

func NewCPEComparer(db core.DB) *cpeComparer {
	return &cpeComparer{
		db: db,
	}
}

func (c *cpeComparer) GetVulns(purl string, notASemverVersion string, componentType string) ([]models.VulnInPackage, error) {
	// convert the purl to a cpe
	cpe, err := normalize.PurlToCPE(purl, componentType)
	if err != nil {
		return nil, err
	}

	// parse the cpe
	// split the criteria into its parts
	parts := strings.Split(cpe, ":")
	part := parts[2]
	vendor := parts[3]
	product := parts[4]
	version, err := utils.SemverFix(parts[5])
	if err != nil {
		return nil, err
	}

	debug := false

	if strings.Contains(purl, "debian/curl") {
		fmt.Println("purl", purl)
		fmt.Println("cpe", cpe)

		debug = true
	}

	cpeMatches := []models.CPEMatch{}

	if debug {
		c.db.Debug().Model(models.CPEMatch{}).Where("(part = ? OR part = '*') AND (vendor = ? OR vendor = '*') AND (product = ? OR product = '*') AND (version = ? OR version = '*') AND (version_end_excluding > ? OR version_end_excluding IS NULL) AND (version_end_including >= ? OR version_end_including IS NULL) AND (version_start_including <= ? OR version_start_including IS NULL) AND (version_start_excluding < ? OR version_start_excluding IS NULL)", part, vendor, product, version, version, version, version, version).Preload("CVEs").Find(&cpeMatches)
	} else {
		c.db.Model(models.CPEMatch{}).Where("(part = ? OR part = '*') AND (vendor = ? OR vendor = '*') AND (product = ? OR product = '*') AND (version = ? OR version = '*') AND (version_end_excluding > ? OR version_end_excluding IS NULL) AND (version_end_including >= ? OR version_end_including IS NULL) AND (version_start_including <= ? OR version_start_including IS NULL) AND (version_start_excluding < ? OR version_start_excluding IS NULL)", part, vendor, product, version, version, version, version, version).Preload("CVEs").Find(&cpeMatches)
	}
	// pg_semver sometimes gets the versions wrong. Lets use Go, which is more reliable todo a version check
	filteredMatches := []models.CPEMatch{}
	for _, cpeMatch := range cpeMatches {
		if debug {
			fmt.Println("found cpe match", cpeMatch.VersionStartIncluding, cpeMatch.VersionEndExcluding, cpeMatch.VersionEndIncluding, version, semver.IsValid("v"+utils.SafeDereference(cpeMatch.VersionStartIncluding)), semver.IsValid("v"+utils.SafeDereference(cpeMatch.VersionEndExcluding)), semver.IsValid("v"+utils.SafeDereference(cpeMatch.VersionEndIncluding)), semver.IsValid("v"+version))
		}
		if cpeMatch.VersionStartIncluding != nil {
			if semver.Compare("v"+*cpeMatch.VersionStartIncluding, "v"+version) > 0 {
				// version start including has to be smaller or equal to the version
				if debug {
					fmt.Println("version start including has to be smaller or equal to the version", "cpeMatch", cpeMatch.VersionStartIncluding, "version", version)
				}
				continue
			}
		}

		if cpeMatch.VersionEndExcluding != nil {
			if semver.Compare("v"+*cpeMatch.VersionEndExcluding, "v"+version) <= 0 {
				// version end excluding has to be bigger than the version
				if debug {
					fmt.Println("version end excluding has to be bigger than the version", "cpeMatch", cpeMatch.VersionEndExcluding, "version", version)
				}
				continue
			} else if debug {
				fmt.Println("version end excluding has to be bigger than the version", "cpeMatch", cpeMatch.VersionEndExcluding, "version",
					version)
			}
		}

		if cpeMatch.VersionEndIncluding != nil {
			if semver.Compare("v"+*cpeMatch.VersionEndIncluding, "v"+version) < 0 {
				// version end including has to be bigger or equal to the version
				if debug {
					fmt.Println("version end including has to be bigger or equal to the version", "cpeMatch", cpeMatch.VersionEndIncluding, "version", version)
				}
				continue
			}
		}
		if debug {
			fmt.Println("version is in the range")
		}
		// if we reach this point, the version is in the range
		filteredMatches = append(filteredMatches, cpeMatch)

	}

	if debug {
		fmt.Println("filteredMatches", filteredMatches)
	}
	vulns := []models.VulnInPackage{}
	for _, cpeMatch := range filteredMatches {
		tmp := cpeMatch
		fixedVersion := tmp.VersionEndExcluding
		if fixedVersion == nil {
			fixedVersion = tmp.VersionEndIncluding
		}

		if debug {
			fmt.Println("fixedVersion", fixedVersion)
		}

		unescapedPurl, err := url.PathUnescape(purl)
		if err != nil {
			return nil, err
		}

		for _, cve := range cpeMatch.CVEs {
			vulns = append(vulns, models.VulnInPackage{
				CVEID:             cve.CVE,
				Purl:              unescapedPurl,
				FixedVersion:      fixedVersion,
				IntroducedVersion: tmp.VersionStartIncluding,
				InstalledVersion:  version,
				CVE:               *cve,
				PackageName:       unescapedPurl,
			})
		}
	}

	return vulns, nil
}
