// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type HTTPController struct {
	db                       core.DB
	sbomScanner              core.SBOMScanner
	cveRepository            core.CveRepository
	componentRepository      core.ComponentRepository
	assetRepository          core.AssetRepository
	assetVersionRepository   core.AssetVersionRepository
	assetVersionService      core.AssetVersionService
	statisticsService        core.StatisticsService
	dependencyVulnRepository core.DependencyVulnRepository
	artifactService          core.ArtifactService
	dependencyVulnService    core.DependencyVulnService
	firstPartyVulnService    core.FirstPartyVulnService

	// mark public to let it be overridden in tests
	core.FireAndForgetSynchronizer
}

func NewHTTPController(db core.DB, cveRepository core.CveRepository, componentRepository core.ComponentRepository, assetRepository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, assetVersionService core.AssetVersionService, statisticsService core.StatisticsService, dependencyVulnService core.DependencyVulnService, firstPartyVulnService core.FirstPartyVulnService, artifactService core.ArtifactService, dependencyVulnRepository core.DependencyVulnRepository) *HTTPController {
	purlComparer := NewPurlComparer(db)

	scanner := NewSBOMScanner(purlComparer, cveRepository)
	return &HTTPController{
		db:                        db,
		sbomScanner:               scanner,
		cveRepository:             cveRepository,
		componentRepository:       componentRepository,
		assetVersionService:       assetVersionService,
		assetRepository:           assetRepository,
		assetVersionRepository:    assetVersionRepository,
		statisticsService:         statisticsService,
		dependencyVulnService:     dependencyVulnService,
		firstPartyVulnService:     firstPartyVulnService,
		FireAndForgetSynchronizer: utils.NewFireAndForgetSynchronizer(),
		artifactService:           artifactService,
		dependencyVulnRepository:  dependencyVulnRepository,
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

// UploadVEX accepts a multipart file upload (field name "file") containing an OpenVEX JSON document.
// It updates existing dependency vulnerabilities on the target asset version and creates vuln events.
func (s HTTPController) UploadVEX(ctx core.Context) error {

	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(ctx.Request().Body, cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		slog.Error("could not decode cyclonedx vex bom", "err", err)
		return echo.NewHTTPError(400, "could not decode vex file as CycloneDX BOM").WithInternal(err)
	}

	ctx.Request().Body.Close()

	asset := core.GetAsset(ctx)
	userID := core.GetSession(ctx).GetUserID()
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")

	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := s.assetVersionRepository.Read(assetVersionName, asset.ID)
	if err != nil {
		slog.Error("could not find asset version", "err", err, "assetVersion", assetVersionName, "assetID", asset.ID)
		return echo.NewHTTPError(404, "could not find asset version").WithInternal(err)
	}
	// load existing dependency vulns for this asset version
	existing, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
	if err != nil {
		slog.Error("could not load dependency vulns", "err", err)
		return echo.NewHTTPError(500, "could not load dependency vulns").WithInternal(err)
	}

	// index by CVE id
	vulnsByCVE := make(map[string][]models.DependencyVuln)
	for _, v := range existing {
		if v.CVE != nil && v.CVE.CVE != "" {
			vulnsByCVE[v.CVE.CVE] = append(vulnsByCVE[v.CVE.CVE], v)
		} else if v.CVEID != nil && *v.CVEID != "" {
			vulnsByCVE[*v.CVEID] = append(vulnsByCVE[*v.CVEID], v)
		}
	}

	updated := 0
	notFound := 0

	// helper to extract cve id from CycloneDX vulnerability id or source url
	extractCVE := func(s string) string {
		if s == "" {
			return ""
		}
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "http") {
			parts := strings.Split(s, "/")
			return parts[len(parts)-1]
		}
		return s
	}

	// iterate vulnerabilities in the CycloneDX BOM
	if bom.Vulnerabilities != nil {
		for _, vuln := range *bom.Vulnerabilities {
			cveID := extractCVE(vuln.ID)
			if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
				cveID = extractCVE(vuln.Source.URL)
			}
			if cveID == "" {
				notFound++
				continue
			}

			cveID = strings.ToUpper(strings.TrimSpace(cveID))

			vlist, ok := vulnsByCVE[cveID]
			if !ok || len(vlist) == 0 {
				notFound++
				continue
			}

			statusType := normalize.MapCDXToStatus(vuln.Analysis)
			if statusType == "" {
				// skip unknown/unspecified statuses
				continue
			}

			justification := "[VEX-Upload]"
			if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
				justification = fmt.Sprintf("[VEX-Upload] %s", vuln.Analysis.Detail)
			}

			for i := range vlist {
				_, err := s.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &vlist[i], statusType, justification, models.MechanicalJustificationType(""), assetVersion.Name) // mechanical justification is not part of cyclonedx spec.
				if err != nil {
					slog.Error("could not update dependency vuln state", "err", err, "cve", cveID)
					continue
				}
				updated++
			}
		}
	}

	return ctx.JSON(200, map[string]int{"updated": updated, "notFound": notFound})
}

func (s *HTTPController) DependencyVulnScan(c core.Context, bom normalize.SBOM) (ScanResponse, error) {
	monitoring.DependencyVulnScanAmount.Inc()
	startTime := time.Now()
	defer func() {
		monitoring.DependencyVulnScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens
	normalizedBom := bom
	asset := core.GetAsset(c)
	org := core.GetOrg(c)
	project := core.GetProject(c)

	userID := core.GetSession(c).GetUserID()

	tag := c.Request().Header.Get("X-Tag")
	defaultBranch := c.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := c.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return scanResults, err
	}

	artifactName := c.Request().Header.Get("X-Artifact-Name")
	if artifactName == "" {
		artifactName = normalize.ArtifactPurl(c.Request().Header.Get("X-Scanner"), org.Slug+"/"+project.Slug+"/"+asset.Slug)
	}

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}

	// save the artifact to the database
	if err := s.artifactService.SaveArtifact(&artifact); err != nil {
		slog.Error("could not save artifact", "err", err)
		return scanResults, err
	}
	// update the sbom in the database in parallel
	s.FireAndForget(func() {
		err = s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifactName, normalizedBom)
		if err != nil {
			slog.Error("could not update sbom", "err", err)
		}
	})

	return s.ScanNormalizedSBOM(org, project, asset, assetVersion, artifact, normalizedBom, userID)
}

func (s *HTTPController) ScanNormalizedSBOM(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom normalize.SBOM, userID string) (ScanResponse, error) {
	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return scanResults, err
	}

	// handle the scan result
	opened, closed, newState, err := s.assetVersionService.HandleScanResult(org, project, asset, &assetVersion, vulns, artifact.ArtifactName, userID)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return scanResults, err
	}

	//Check if we want to create an issue for this assetVersion

	s.FireAndForget(func() {
		err := s.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, append(newState, closed...))
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	s.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := s.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)

		}

		// save the asset
		if err := s.artifactService.SaveArtifact(&artifact); err != nil {
			slog.Error("could not save artifact", "err", err)
		}
	})

	scanResults.AmountOpened = len(opened) //Fill in the results
	scanResults.AmountClosed = len(closed)
	scanResults.DependencyVulns = utils.Map(newState, vuln.DependencyVulnToDto)

	return scanResults, nil
}

func (s *HTTPController) FirstPartyVulnScan(ctx core.Context) error {

	monitoring.FirstPartyScanAmount.Inc()
	startTime := time.Now()
	defer func() {
		monitoring.FirstPartyScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	var sarifScan common.SarifResult

	defer ctx.Request().Body.Close()

	if err := ctx.Bind(&sarifScan); err != nil {
		return err
	}

	org := core.GetOrg(ctx)
	project := core.GetProject(ctx)

	asset := core.GetAsset(ctx)
	userID := core.GetSession(ctx).GetUserID()

	tag := ctx.Request().Header.Get("X-Tag")

	defaultBranch := ctx.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
		defaultBranch = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	scannerID := ctx.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no X-Scanner header found")
		return ctx.JSON(400, map[string]string{
			"error": "no X-Scanner header found",
		})
	}

	// handle the scan result
	opened, closed, newState, err := s.assetVersionService.HandleFirstPartyVulnResult(org, project, asset, &assetVersion, sarifScan, scannerID, userID)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return ctx.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	s.FireAndForget(func() {
		err := s.firstPartyVulnService.SyncIssues(org, project, asset, assetVersion, append(newState, closed...))
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	err = s.assetVersionRepository.Save(nil, &assetVersion)
	if err != nil {
		slog.Error("could not save asset", "err", err)
	}

	return ctx.JSON(200, FirstPartyScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		FirstPartyVulns: utils.Map(newState, vuln.FirstPartyVulnToDto),
	})
}

func (s *HTTPController) ScanDependencyVulnFromProject(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	defer c.Request().Body.Close()
	if err := decoder.Decode(bom); err != nil {
		return err
	}

	scanResults, err := s.DependencyVulnScan(c, normalize.FromCdxBom(bom, true))
	if err != nil {
		return err
	}

	return c.JSON(200, scanResults)
}

func (s *HTTPController) ScanSbomFile(c core.Context) error {
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

	scanResults, err := s.DependencyVulnScan(c, normalize.FromCdxBom(bom, true))
	if err != nil {
		return err
	}

	return c.JSON(200, scanResults)

}
