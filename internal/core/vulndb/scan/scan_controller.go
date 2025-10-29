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
	artifactName := ctx.Request().Header.Get("X-Artifact-Name")
	org := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	tag := ctx.Request().Header.Get("X-Tag")

	defaultBranch := ctx.Request().Header.Get("X-Asset-Default-Branch")
	origin := ctx.Request().Header.Get("X-Origin")
	if origin == "" {
		origin = "vex-upload"
	}

	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return echo.NewHTTPError(500, "could not find or create asset version").WithInternal(err)
	}

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersionName,
		AssetID:          asset.ID,
	}

	// save the artifact to the database
	if err := s.artifactService.SaveArtifact(&artifact); err != nil {
		slog.Error("could not save artifact", "err", err)
		return echo.NewHTTPError(500, "could not save artifact").WithInternal(err)
	}

	vulns, err := s.artifactService.SyncUpstreamBoms([]normalize.SBOM{normalize.FromCdxBom(&bom, artifactName, origin)}, org, project, asset, assetVersion, artifact, userID)
	if err != nil {
		slog.Error("could not scan vex", "err", err)
		return err
	}

	s.FireAndForget(func() {
		err := s.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns)
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

	return ctx.JSON(200, nil)
}

func (s *HTTPController) DependencyVulnScan(c core.Context, bom *cdx.BOM) (ScanResponse, error) {
	monitoring.DependencyVulnScanAmount.Inc()
	startTime := time.Now()
	defer func() {
		monitoring.DependencyVulnScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens

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
	artifactName := c.Request().Header.Get("X-Artifact-Name")
	origin := c.Request().Header.Get("X-Origin")
	normalized := normalize.FromCdxBom(bom, artifactName, utils.OrDefault(utils.EmptyThenNil(origin), "DEFAULT"))

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return scanResults, err
	}

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
	// do NOT update the sbom in parallel, because we load the components during the scan from the database
	err = s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifactName, normalized, models.UpstreamStateInternal)
	if err != nil {
		slog.Error("could not update sbom", "err", err)
	}

	return s.ScanNormalizedSBOM(org, project, asset, assetVersion, artifact, normalized, userID)
}

func (s *HTTPController) ScanNormalizedSBOM(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom normalize.SBOM, userID string) (ScanResponse, error) {
	scanResults := ScanResponse{} //Initialize empty struct to return when an error happens
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return scanResults, err
	}

	// handle the scan result
	opened, closed, newState, err := s.assetVersionService.HandleScanResult(org, project, asset, &assetVersion, vulns, artifact.ArtifactName, userID, models.UpstreamStateInternal)
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
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	scanResults, err := s.DependencyVulnScan(c, bom)
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
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	// if no origin is provided via header set it ourselves
	origin := c.Request().Header.Get("X-Origin")
	if origin == "" {
		origin = "sbom-file-upload"
		c.Request().Header.Set("X-Origin", origin)
	}

	scanResults, err := s.DependencyVulnScan(c, bom)
	if err != nil {
		return err
	}

	return c.JSON(200, scanResults)

}
