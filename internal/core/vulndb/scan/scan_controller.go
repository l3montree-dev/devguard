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
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type cveRepository interface {
	FindAll(cveIDs []string) ([]models.CVE, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
}

type assetRepository interface {
	Save(tx core.DB, asset *models.Asset) error
}

type httpController struct {
	db                  core.DB
	sbomScanner         *sbomScanner
	cveRepository       cveRepository
	componentRepository componentRepository
	assetRepository     assetRepository
}

func NewHttpController(db core.DB, cveRepository cveRepository, componentRepository componentRepository, assetRepository assetRepository) *httpController {
	cpeComparer := NewCPEComparer(db)
	purlComparer := NewPurlComparer(db)

	scanner := NewSBOMScanner(cpeComparer, purlComparer)
	return &httpController{
		db:                  db,
		sbomScanner:         scanner,
		cveRepository:       cveRepository,
		componentRepository: componentRepository,
		assetRepository:     assetRepository,
	}
}

func purlOrCpe(component cdx.Component) string {
	if component.PackageURL != "" {
		return component.PackageURL
	}
	return component.CPE
}

func urlDecode(purl string) (string, error) {
	p, err := url.PathUnescape(purl)
	if err != nil {
		return "", err
	}
	return p, nil
}

func (s *httpController) saveAssetComponents(c core.Context, sbom *cdx.BOM) {
	// update the sbom for the asset in the database.
	asset := core.GetAsset(c)

	components := make([]models.Component, 0)
	// create all components
	for _, component := range *sbom.Dependencies {
		// check if this is the asset itself.
		if component.Ref == sbom.Metadata.Component.BOMRef {
			continue
		}

		dependencies := make([]models.Component, 0)
		for _, dep := range *component.Dependencies {
			p, err := urlDecode(dep)
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			dependencies = append(dependencies, models.Component{
				PurlOrCpe: p,
			})
		}
		// check if the component is already in the database
		// if not, create it
		// if it is, update it
		p, err := urlDecode(component.Ref)
		if err != nil {
			slog.Error("could not decode purl", "err", err)
			continue
		}
		components = append(components, models.Component{
			PurlOrCpe: p,
			DependsOn: dependencies,
		})
	}
	// save all components in the database
	if err := s.componentRepository.SaveBatch(nil, components); err != nil {
		slog.Error("could not save components", "err", err)
	} else {
		slog.Info("saved components", "asset", asset.GetID().String(), "count", len(components))
	}

	// get the direct dependencies of the asset
	// ref: https://github.com/CycloneDX/cdxgen/issues/650
	directDependencies := make([]models.Component, 0)
	for _, component := range *sbom.Components {
		if component.Scope == cdx.ScopeRequired {
			p, err := urlDecode(purlOrCpe(component))
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			directDependencies = append(directDependencies, models.Component{
				PurlOrCpe: p,
			})
		}
	}
	asset.Components = directDependencies
	// save the direct dependencies of the asset
	if err := s.assetRepository.Save(nil, &asset); err != nil {
		slog.Error("could not save direct dependencies", "err", err)
	} else {
		slog.Info("saved direct dependencies", "asset", asset.GetID().String(), "count", len(directDependencies))
	}
}

func (s *httpController) Scan(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}
	// update the sbom in the database in parallel
	go s.saveAssetComponents(c, bom)

	// scan the bom we just retrieved.
	vulns, err := s.sbomScanner.Scan(bom)
	if err != nil {
		slog.Error("could not scan file", "err", err)
		return c.JSON(500, map[string]string{"error": "could not scan file"})
	}

	// create flaws out of those vulnerabilities
	flaws := []models.Flaw{}
	cveIDs := []string{}
	for _, vuln := range vulns {
		cveIDs = append(cveIDs, vuln.CVEID)
		flaw := models.Flaw{
			CVEID:     vuln.CVEID,
			ScannerID: "github.com/l3montree-dev/flawfix/cmd/flawfind",
		}
		flaw.SetAdditionalData(map[string]any{
			"introducedVersion": vuln.GetIntroducedVersion(),
			"fixedVersion":      vuln.GetFixedVersion(),
			"packageName":       vuln.PackageName,
		})
		flaws = append(flaws, flaw)
	}
	// find all cves in our database and match them.
	cves, err := s.cveRepository.FindAll(cveIDs)
	if err != nil {
		slog.Error("could not find cves", "err", err)
		return c.JSON(500, map[string]string{"error": "could not find cves"})
	}

	// match the cves with the found vulnerabilities
	for _, cve := range cves {
		for j, flaw := range flaws {
			if cve.CVE == flaw.CVEID {
				tmp := cve
				flaws[j].CVE = &tmp
			}
		}
	}

	return c.JSON(200, flaws)
}
