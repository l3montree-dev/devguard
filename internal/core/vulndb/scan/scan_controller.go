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

type assetService interface {
	HandleScanResult(user string, scannerID string, asset models.Asset, flaws []models.Flaw)
	UpdateSBOM(asset models.Asset, sbom *cdx.BOM)
}

type httpController struct {
	db                  core.DB
	sbomScanner         *sbomScanner
	cveRepository       cveRepository
	componentRepository componentRepository
	assetService        assetService
}

func NewHttpController(db core.DB, cveRepository cveRepository, componentRepository componentRepository, assetService assetService) *httpController {
	cpeComparer := NewCPEComparer(db)
	purlComparer := NewPurlComparer(db)

	scanner := NewSBOMScanner(cpeComparer, purlComparer, cveRepository)
	return &httpController{
		db:                  db,
		sbomScanner:         scanner,
		cveRepository:       cveRepository,
		componentRepository: componentRepository,
		assetService:        assetService,
	}
}

func (s *httpController) Scan(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}
	asset := core.GetAsset(c)

	userID := core.GetSession(c).GetUserID()

	// update the sbom in the database in parallel
	go s.assetService.UpdateSBOM(asset, bom)

	// scan the bom we just retrieved.
	vulns, err := s.sbomScanner.Scan(bom)
	if err != nil {
		slog.Error("could not scan file", "err", err)
		return c.JSON(500, map[string]string{"error": "could not scan file"})
	}

	scannerID := "github.com/l3montree-dev/flawfix/cmd/flawfind"

	// create flaws out of those vulnerabilities
	flaws := []models.Flaw{}

	for _, vuln := range vulns {
		v := vuln

		purlWithVersion, err := url.PathUnescape(vuln.PurlWithVersion)
		if err != nil {
			slog.Error("could not unescape purl", "err", err)
			continue
		}
		// check if the component has an cve

		flaw := models.Flaw{
			AssetID:            asset.ID,
			CVEID:              v.CVEID,
			ScannerID:          scannerID,
			ComponentPurlOrCpe: purlWithVersion,
			CVE:                &v.CVE,
		}

		flaw.SetArbitraryJsonData(map[string]any{
			"introducedVersion": v.GetIntroducedVersion(),
			"fixedVersion":      v.GetFixedVersion(),
			"packageName":       v.PackageName,
			"cveId":             v.CVEID,
		})
		flaws = append(flaws, flaw)
	}

	// let the asset service handle the new scan result - we do not need
	// any return value from that process - even if it fails, we should return the current flaws
	go s.assetService.HandleScanResult(userID, scannerID, asset, flaws)

	return c.JSON(200, flaws)
}
