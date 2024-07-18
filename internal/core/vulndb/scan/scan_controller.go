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
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type cveRepository interface {
	FindAll(cveIDs []string) ([]models.CVE, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadAssetComponents(tx core.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error)
}

type assetService interface {
	HandleScanResult(user string, scannerID string, asset models.Asset, flaws []models.Flaw) (amountOpened int, amountClosed int, newState []models.Flaw, err error)
	UpdateSBOM(asset models.Asset, scanType string, version string, sbom *cdx.BOM) error
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

type ScanResponse struct {
	AmountOpened int            `json:"amountOpened"`
	AmountClosed int            `json:"amountClosed"`
	Flaws        []flaw.FlawDTO `json:"flaws"`
}

func (s *httpController) Scan(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}
	assetObj := core.GetAsset(c)

	userID := core.GetSession(c).GetUserID()

	// get the X-Asset-Version header
	version := c.Request().Header.Get("X-Asset-Version")
	if version == "" {
		slog.Error("no version header found")
		return c.JSON(400, map[string]string{"error": "no version header found"})
	}

	scanType := c.Request().Header.Get("X-Scan-Type")
	if scanType == "" {
		slog.Error("no scan type header found")
		return c.JSON(400, map[string]string{
			"error": "no scan type header found",
		})
	}

	var err error
	version, err = utils.SemverFix(version)
	// check if valid semver
	if err != nil {
		slog.Error("invalid semver version", "version", version)
		return c.JSON(400, map[string]string{"error": "invalid semver version"})
	}

	// update the sbom in the database in parallel
	if err := s.assetService.UpdateSBOM(assetObj, scanType, version, bom); err != nil {
		slog.Error("could not update sbom", "err", err)
		return c.JSON(500, map[string]string{"error": "could not update sbom"})
	}

	// scan the bom we just retrieved.
	vulns, err := s.sbomScanner.Scan(bom)
	if err != nil {
		slog.Error("could not scan file", "err", err)
		return c.JSON(500, map[string]string{"error": "could not scan file"})
	}

	scannerID := "github.com/l3montree-dev/devguard/cmd/devguard-scanner"

	// create flaws out of those vulnerabilities
	flaws := []models.Flaw{}

	// load all asset components again and build a dependency tree
	assetComponents, err := s.componentRepository.LoadAssetComponents(nil, assetObj, scanType, version)
	if err != nil {
		slog.Error("could not load asset components", "err", err)
		return c.JSON(500, map[string]string{"error": "could not load asset components"})
	}
	// build a dependency tree
	tree := asset.BuildDependencyTree(assetComponents)
	// calculate the depth of each component
	depthMap := make(map[string]int)

	asset.CalculateDepth(tree.Root, 0, depthMap)
	// now we have the depth.

	for _, vuln := range vulns {
		v := vuln

		purlWithVersion, err := url.PathUnescape(vuln.PurlWithVersion)
		if err != nil {
			slog.Error("could not unescape purl", "err", err)
			continue
		}
		// check if the component has an cve

		flaw := models.Flaw{
			AssetID:            assetObj.ID,
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
			"installedVersion":  v.InstalledVersion,
			"componentDepth":    depthMap[purlWithVersion],
		})
		flaws = append(flaws, flaw)
	}

	// let the asset service handle the new scan result - we do not need
	// any return value from that process - even if it fails, we should return the current flaws
	amountOpened, amountClose, newState, err := s.assetService.HandleScanResult(userID, scannerID, assetObj, flaws)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return c.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	return c.JSON(200, ScanResponse{
		AmountOpened: amountOpened,
		AmountClosed: amountClose,
		Flaws: utils.Map(newState, func(f models.Flaw) flaw.FlawDTO {
			return flaw.FlawDTO{
				ID:                 f.ID,
				ScannerID:          f.AssetID.String(),
				State:              f.State,
				CVE:                f.CVE,
				Component:          f.Component,
				CVEID:              f.CVEID,
				ComponentPurlOrCpe: f.ComponentPurlOrCpe,
				Effort:             f.Effort,
				RiskAssessment:     f.RiskAssessment,
				RawRiskAssessment:  f.RawRiskAssessment,
				Priority:           f.Priority,
				ArbitraryJsonData:  f.GetArbitraryJsonData(),
				LastDetected:       f.LastDetected,
				CreatedAt:          f.CreatedAt,
			}
		})})
}
