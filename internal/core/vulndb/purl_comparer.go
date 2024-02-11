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

package vulndb

import (
	"log/slog"

	"net/url"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type PurlComparer struct {
	db core.DB
}

func NewPurlComparer(db core.DB) *PurlComparer {
	return &PurlComparer{
		db: db,
	}
}

func stringOrNil(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (comparer *PurlComparer) GetCVEs(purl string) ([]CVE, error) {
	// parse the purl
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse purl")
	}

	version, err := utils.SemverFix(p.Version)
	if err != nil {
		return nil, err
	}

	affectedPackages := []AffectedPackage{}
	p.Version = ""

	pURL, err := url.PathUnescape(p.ToString())
	if err != nil {
		return nil, errors.Wrap(err, "could not unescape purl path")
	}
	// check if the package is present in the database
	comparer.db.Model(&AffectedPackage{}).Where("p_url = ?", pURL).Where(
		comparer.db.Where(
			"version = ?", version).
			Or("semver_introduced IS NULL AND semver_fixed > ?", version).
			Or("semver_introduced < ? AND semver_fixed IS NULL", version).
			Or("semver_introduced < ? AND semver_fixed > ?", version, version),
	).Preload("CVE").Find(&affectedPackages)

	p.Version = version
	for _, pkg := range affectedPackages {
		for _, cve := range pkg.CVE {
			slog.Info("found cve", "cve", cve.CVE, "purl", pURL, "installedVersion", version, "fixedVersion", stringOrNil(pkg.SemverFixed), "introducedVersion", stringOrNil(pkg.SemverIntroduced))
		}
	}

	return nil, nil
}
