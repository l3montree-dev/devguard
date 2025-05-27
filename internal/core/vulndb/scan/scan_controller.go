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
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type httpController struct {
	db                     core.DB
	sbomScanner            *sbomScanner
	cveRepository          core.CveRepository
	componentRepository    core.ComponentRepository
	assetRepository        core.AssetRepository
	assetVersionRepository core.AssetVersionRepository
	assetVersionService    core.AssetVersionService
	statisticsService      core.StatisticsService

	dependencyVulnService core.DependencyVulnService
}

func NewHttpController(db core.DB, cveRepository core.CveRepository, componentRepository core.ComponentRepository, assetRepository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, assetVersionService core.AssetVersionService, statisticsService core.StatisticsService, dependencyVulnService core.DependencyVulnService) *httpController {
	cpeComparer := NewCPEComparer(db)
	purlComparer := NewPurlComparer(db)

	scanner := NewSBOMScanner(cpeComparer, purlComparer, cveRepository)
	return &httpController{
		db:                     db,
		sbomScanner:            scanner,
		cveRepository:          cveRepository,
		componentRepository:    componentRepository,
		assetVersionService:    assetVersionService,
		assetRepository:        assetRepository,
		assetVersionRepository: assetVersionRepository,
		statisticsService:      statisticsService,
		dependencyVulnService:  dependencyVulnService,
	}
}

type ScanResponse struct {
	AmountOpened    int                      `json:"amountOpened"`
	AmountClosed    int                      `json:"amountClosed"`
	DependencyVulns []vuln.DependencyVulnDTO `json:"dependencyVulns"`
}

type FirstPartyScanResponse struct {
	AmountOpened    int                      `json:"amountOpened"`
	AmountClosed    int                      `json:"amountClosed"`
	FirstPartyVulns []vuln.FirstPartyVulnDTO `json:"firstPartyVulns"`
}

func DependencyVulnScan(c core.Context, bom normalize.SBOM, s *httpController) (ScanResponse, error) {

	monitoring.DependencyVulnScanAmount.Inc()
	startTime := time.Now()
	defer func() {
		monitoring.DependencyVulnScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens
	normalizedBom := bom
	asset := core.GetAsset(c)

	userID := core.GetSession(c).GetUserID()

	tag := c.Request().Header.Get("X-Tag")

	defaultBranch := c.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := c.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
		defaultBranch = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag, defaultBranch)
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return scanResults, err
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no X-Scanner header found")
		return scanResults, err
	}

	// update the sbom in the database in parallel
	if err := s.assetVersionService.UpdateSBOM(assetVersion, scannerID, normalizedBom); err != nil {
		slog.Error("could not update sbom", "err", err)
		return scanResults, err
	}
	return ScanNormalizedSBOM(s, asset, assetVersion, normalizedBom, scannerID, userID)
}

func ScanNormalizedSBOM(s *httpController, asset models.Asset, assetVersion models.AssetVersion, normalizedBom normalize.SBOM, scannerID string, userID string) (ScanResponse, error) {
	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return scanResults, err
	}

	// handle the scan result
	opened, closed, newState, err := s.assetVersionService.HandleScanResult(asset, &assetVersion, vulns, scannerID, userID)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return scanResults, err
	}

	//Check if we want to create an issue for this assetVersion
	if s.dependencyVulnService.ShouldCreateIssues(assetVersion) {
		go func() {
			err := s.dependencyVulnService.CreateIssuesForVulnsIfThresholdExceeded(asset, opened)
			if err != nil {
				slog.Error("could not create issues for vulnerabilities", "err", err)
			}
			// close the fixed vulnerabilities
			err = s.dependencyVulnService.CloseIssuesAsFixed(asset, closed)
			if err != nil {
				slog.Error("could not close issues for vulnerabilities", "err", err)
			}
		}()
	}

	slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
	if err := s.statisticsService.UpdateAssetRiskAggregation(&assetVersion, asset.ID, utils.OrDefault(assetVersion.LastHistoryUpdate, assetVersion.CreatedAt), time.Now(), true); err != nil {
		slog.Error("could not recalculate risk history", "err", err)
		return scanResults, err
	}

	// save the asset
	if err := s.assetVersionRepository.Save(nil, &assetVersion); err != nil {
		slog.Error("could not save asset", "err", err)
		return scanResults, err
	}

	scanResults.AmountOpened = len(opened) //Fill in the results
	scanResults.AmountClosed = len(closed)
	scanResults.DependencyVulns = utils.Map(newState, vuln.DependencyVulnToDto)

	return scanResults, nil
}

func (s *httpController) FirstPartyVulnScan(c core.Context) error {

	monitoring.FirstPartyScanAmount.Inc()
	startTime := time.Now()
	defer func() {
		monitoring.FirstPartyScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	var sarifScan common.SarifResult

	defer c.Request().Body.Close()

	if err := c.Bind(&sarifScan); err != nil {
		return err
	}

	asset := core.GetAsset(c)
	userID := core.GetSession(c).GetUserID()

	tag := c.Request().Header.Get("X-Tag")

	defaultBranch := c.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := c.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag, defaultBranch)
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return c.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no X-Scanner header found")
		return c.JSON(400, map[string]string{
			"error": "no X-Scanner header found",
		})
	}

	// handle the scan result
	amountOpened, amountClose, newState, err := s.assetVersionService.HandleFirstPartyVulnResult(asset, &assetVersion, sarifScan, scannerID, userID)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return c.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	err = s.assetVersionRepository.Save(nil, &assetVersion)
	if err != nil {
		slog.Error("could not save asset", "err", err)
	}

	return c.JSON(200, FirstPartyScanResponse{
		AmountOpened:    amountOpened,
		AmountClosed:    amountClose,
		FirstPartyVulns: utils.Map(newState, vuln.FirstPartyVulnToDto),
	})
}

func (s *httpController) ScanDependencyVulnFromProject(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	defer c.Request().Body.Close()
	if err := decoder.Decode(bom); err != nil {
		return err
	}

	scanResults, err := DependencyVulnScan(c, normalize.FromCdxBom(bom, true), s)
	if err != nil {
		return err
	}
	return c.JSON(200, scanResults)

}

func (s *httpController) ScanSbomFile(c core.Context) error {

	var maxSize int64 = 16 * 1024 * 1024 //Max Upload Size 16mb
	err := c.Request().ParseMultipartForm(maxSize)
	if err != nil {
		slog.Error("error when parsing data")
		return err
	}
	file, _, err := c.Request().FormFile("file")
	if err != nil {
		slog.Error("error when forming file")
		return err
	}
	defer file.Close()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(file, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}

	scanResults, err := DependencyVulnScan(c, normalize.FromCdxBom(bom, true), s)
	if err != nil {
		return err
	}
	return c.JSON(200, scanResults)

}
