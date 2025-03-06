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
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type cveRepository interface {
	FindAll(cveIDs []string) ([]models.CVE, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadComponents(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID, version string) ([]models.ComponentDependency, error)
}

type assetVersionService interface {
	HandleScanResult(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool) (amountOpened int, amountClose int, newState []models.DependencyVuln, err error)
	UpdateSBOM(asset models.AssetVersion, scanner string, version string, sbom normalize.SBOM) error

	HandleFirstPartyVulnResult(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool) (int, int, []models.FirstPartyVulnerability, error)
}

type assetRepository interface {
	GetAllAssetsFromDB() ([]models.Asset, error)
	Save(tx core.DB, asset *models.Asset) error
}

type assetVersionRepository interface {
	FindOrCreate(assetVersionName string, assetID uuid.UUID, tag string, defaultBranch string) (models.AssetVersion, error)
	Save(tx core.DB, assetVersion *models.AssetVersion) error
}

type statisticsService interface {
	UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, updateProject bool) error
}

type httpController struct {
	db                     core.DB
	sbomScanner            *sbomScanner
	cveRepository          cveRepository
	componentRepository    componentRepository
	assetRepository        assetRepository
	assetVersionRepository assetVersionRepository
	assetVersionService    assetVersionService
	statisticsService      statisticsService
}

func NewHttpController(db core.DB, cveRepository cveRepository, componentRepository componentRepository, assetRepository assetRepository, assetVersionRepository assetVersionRepository, assetVersionService assetVersionService, statisticsService statisticsService) *httpController {
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
	}
}

type ScanResponse struct {
	AmountOpened    int                                `json:"amountOpened"`
	AmountClosed    int                                `json:"amountClosed"`
	DependencyVulns []dependencyVuln.DependencyVulnDTO `json:"dependencyVulns"`
}

type FirstPartyScanResponse struct {
	AmountOpened    int                                `json:"amountOpened"`
	AmountClosed    int                                `json:"amountClosed"`
	FirstPartyVulns []dependencyVuln.FirstPartyVulnDTO `json:"firstPartyVulns"`
}

func DependencyVulnScan(c core.Context, bom normalize.SBOM, s *httpController) (ScanResponse, error) {
	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens

	normalizedBom := bom
	asset := core.GetAsset(c)

	userID := core.GetSession(c).GetUserID()

	// get the X-Asset-Version header
	version := c.Request().Header.Get("X-Asset-Version")
	if version == "" {
		version = models.NoVersion
	}

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

	scanner := c.Request().Header.Get("X-Scanner")
	if scanner == "" {
		slog.Error("no X-Scanner header found")
		return scanResults, err
	}

	if version != models.NoVersion {
		var err error
		version, err = normalize.SemverFix(version)
		// check if valid semver
		if err != nil {
			slog.Error("invalid semver version", "version", version)
			return scanResults, err
		}
	}
	//check if risk management is enabled
	riskManagementEnabled := c.Request().Header.Get("X-Risk-Management")
	doRiskManagement := riskManagementEnabled != "false"

	if doRiskManagement {
		// update the sbom in the database in parallel
		if err := s.assetVersionService.UpdateSBOM(assetVersion, scanner, version, normalizedBom); err != nil {
			slog.Error("could not update sbom", "err", err)
			return scanResults, err
		}

	}

	// scan the bom we just retrieved.
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return scanResults, err
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no scanner id provided")
		return scanResults, err
	}

	// handle the scan result
	amountOpened, amountClose, newState, err := s.assetVersionService.HandleScanResult(asset, &assetVersion, vulns, scannerID, version, scannerID, userID, doRiskManagement)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return scanResults, err
	}

	err = createIssuesForVulns(newState, c)
	if err != nil {
		return scanResults, err
	}

	if doRiskManagement {
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
	}
	scanResults.AmountOpened = amountOpened //Fill in the results
	scanResults.AmountClosed = amountClose
	scanResults.DependencyVulns = utils.Map(newState, dependencyVuln.DependencyVulnToDto)

	return scanResults, nil
}

func (s *httpController) FirstPartyVulnScan(c core.Context) error {
	var sarifScan models.SarifResult
	if err := c.Bind(&sarifScan); err != nil {
		return err
	}

	asset := core.GetAsset(c)
	userID := core.GetSession(c).GetUserID()

	// get the X-Asset-Version header

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

	scanner := c.Request().Header.Get("X-Scanner")
	if scanner == "" {
		slog.Error("no X-Scanner header found")
		return c.JSON(400, map[string]string{
			"error": "no X-Scanner header found",
		})
	}

	//check if risk management is enabled
	riskManagementEnabled := c.Request().Header.Get("X-Risk-Management")
	doRiskManagement := riskManagementEnabled != "false"

	// handle the scan result
	amountOpened, amountClose, newState, err := s.assetVersionService.HandleFirstPartyVulnResult(asset, &assetVersion, sarifScan, scanner, userID, true)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return c.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	if doRiskManagement {
		err := s.assetVersionRepository.Save(nil, &assetVersion)
		if err != nil {
			slog.Error("could not save asset", "err", err)
		}
	}

	return c.JSON(200, FirstPartyScanResponse{
		AmountOpened:    amountOpened,
		AmountClosed:    amountClose,
		FirstPartyVulns: utils.Map(newState, dependencyVuln.FirstPartyVulnToDto),
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
		fmt.Printf("error when parsing data")
		return err
	}
	file, _, err := c.Request().FormFile("file")
	if err != nil {
		fmt.Printf("error when forming file")
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

// function to check whether the provided vulnerabilities in a given asset exceeds their respective thresholds and create a ticket for it if they do so
func createIssuesForVulns(vulnList []models.DependencyVuln, c core.Context) error {
	asset := core.GetAsset(c)
	thirdPartyIntegration := core.GetThirdPartyIntegration(c)

	riskThreshold := asset.RiskAutomaticTicketThreshold
	cvssThreshold := asset.CVSSAutomaticTicketThreshold

	//Check if no automatic Issues are wanted by the user
	if riskThreshold == nil && cvssThreshold == nil {
		fmt.Printf("Both null")
		return nil
	}

	//Determine whether to scan for both risk and cvss or just 1 of them
	if riskThreshold != nil && cvssThreshold != nil {
		fmt.Printf("Both")
		for _, vulnerability := range vulnList {
			if *vulnerability.RawRiskAssessment >= *asset.RiskAutomaticTicketThreshold || vulnerability.CVE.CVSS >= float32(*asset.CVSSAutomaticTicketThreshold) {
				err := thirdPartyIntegration.HandleEvent(core.ManualMitigateEvent{
					Ctx: c,
				})
				if err != nil {
					return err
				}
			}

		}
	} else {
		if riskThreshold != nil {
			fmt.Printf("Only risk")
			for _, vulnerability := range vulnList {
				fmt.Printf("\n%f > %f\n ", *vulnerability.RawRiskAssessment, *asset.RiskAutomaticTicketThreshold)
				if *vulnerability.RawRiskAssessment >= *asset.RiskAutomaticTicketThreshold {
					err := thirdPartyIntegration.HandleEvent(core.ManualMitigateEvent{
						Ctx: c,
					})
					if err != nil {
						return err
					}
				}
			}
		} else if cvssThreshold != nil {
			fmt.Printf("Only cvss")
			for _, vulnerability := range vulnList {
				fmt.Printf("\n%f > %f\n ", vulnerability.CVE.CVSS, float32(*asset.CVSSAutomaticTicketThreshold))
				if vulnerability.CVE.CVSS >= float32(*asset.CVSSAutomaticTicketThreshold) {
					err := thirdPartyIntegration.HandleEvent(core.ManualMitigateEvent{
						Ctx: c,
					})
					if err != nil {
						return err
					}
				}
			}
		}

	}
	return nil
}
