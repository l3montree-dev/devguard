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
	"net/url"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type purlComparer struct {
	db core.DB
}

func NewPurlComparer(db core.DB) *purlComparer {
	return &purlComparer{
		db: db,
	}
}

func (comparer *purlComparer) GetVulnsForAll(purls []string) ([]models.VulnInPackage, error) {
	g := errgroup.Group{}
	g.SetLimit(10) // magic concurrency number - this was just a quick test against a local installed postgresql
	results := make([][]models.VulnInPackage, len(purls))
	for i, purl := range purls {
		p := purl
		itmp := i
		g.Go(func() error {
			vulns, err := comparer.GetVulns(p)
			if err != nil {
				return err
			}
			results[itmp] = vulns
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return utils.Flat(results), nil
}

func (comparer *purlComparer) GetVulns(purl string) ([]models.VulnInPackage, error) {
	// parse the purl
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse purl")
	}

	version, err := utils.SemverFix(p.Version)
	if err != nil {
		return nil, err
	}

	affectedComponents := []models.AffectedComponent{}
	p.Version = ""

	pURL, err := url.PathUnescape(p.ToString())
	if err != nil {
		return nil, errors.Wrap(err, "could not unescape purl path")
	}
	// check if the package is present in the database
	comparer.db.Model(&models.AffectedComponent{}).Where("purl = ?", pURL).Where(
		comparer.db.Where(
			"version = ?", version).
			Or("semver_introduced IS NULL AND semver_fixed > ?", version).
			Or("semver_introduced < ? AND semver_fixed IS NULL", version).
			Or("semver_introduced < ? AND semver_fixed > ?", version, version),
	).Preload("CVE").Find(&affectedComponents)

	vulnerabilities := []models.VulnInPackage{}

	// transform the affected packages to the vulnInPackage struct
	for _, affectedComponent := range affectedComponents {
		for _, cve := range affectedComponent.CVE {
			// append the cve to the vulnerabilities
			vulnerabilities = append(vulnerabilities, models.VulnInPackage{
				CVEID:             cve.CVE,
				FixedVersion:      affectedComponent.SemverFixed,
				IntroducedVersion: affectedComponent.SemverIntroduced,
				PackageName:       affectedComponent.PURL,
				PurlWithVersion:   purl,
				CVE:               cve,
			})
		}
	}

	return vulnerabilities, nil
}
