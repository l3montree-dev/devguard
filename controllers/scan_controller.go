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

package controllers

import (
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ScanController struct {
	componentRepository      shared.ComponentRepository
	assetRepository          shared.AssetRepository
	assetVersionRepository   shared.AssetVersionRepository
	assetVersionService      shared.AssetVersionService
	statisticsService        shared.StatisticsService
	dependencyVulnRepository shared.DependencyVulnRepository
	artifactService          shared.ArtifactService
	dependencyVulnService    shared.DependencyVulnService
	firstPartyVulnService    shared.FirstPartyVulnService
	shared.ScanService
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
}

func NewScanController(scanService shared.ScanService, componentRepository shared.ComponentRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, assetVersionService shared.AssetVersionService, statisticsService shared.StatisticsService, dependencyVulnService shared.DependencyVulnService, firstPartyVulnService shared.FirstPartyVulnService, artifactService shared.ArtifactService, dependencyVulnRepository shared.DependencyVulnRepository, synchronizer utils.FireAndForgetSynchronizer) *ScanController {
	return &ScanController{
		componentRepository:       componentRepository,
		assetVersionService:       assetVersionService,
		assetRepository:           assetRepository,
		assetVersionRepository:    assetVersionRepository,
		statisticsService:         statisticsService,
		dependencyVulnService:     dependencyVulnService,
		firstPartyVulnService:     firstPartyVulnService,
		FireAndForgetSynchronizer: synchronizer,
		artifactService:           artifactService,
		dependencyVulnRepository:  dependencyVulnRepository,
		ScanService:               scanService,
	}
}

// UploadVEX accepts a multipart file upload (field name "file") containing an OpenVEX JSON document.
// It updates existing dependency vulnerabilities on the target asset version and creates vuln events.
func (s ScanController) UploadVEX(ctx shared.Context) error {
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(ctx.Request().Body, cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		slog.Error("could not decode cyclonedx vex bom", "err", err)
		return echo.NewHTTPError(400, "could not decode vex file as CycloneDX BOM").WithInternal(err)
	}

	ctx.Request().Body.Close()

	asset := shared.GetAsset(ctx)
	userID := shared.GetSession(ctx).GetUserID()
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	artifactName := ctx.Request().Header.Get("X-Artifact-Name")
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
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

	if artifactName == "" {
		artifactName = normalize.ArtifactPurl(ctx.Request().Header.Get("X-Scanner"), org.Slug+"/"+project.Slug+"/"+asset.Slug)
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

	externalURLs := []string{}
	// check if vex url is present in the bom metadata
	if bom.ExternalReferences != nil {
		for _, ref := range *bom.ExternalReferences {
			if ref.Type == cdx.ERTypeExploitabilityStatement {
				externalURLs = append(externalURLs, ref.URL)
			}
		}
	}
	upstreamBOMS := []*normalize.CdxBom{}
	// check if there are components or vulnerabilities in the bom
	if (bom.Components != nil && len(*bom.Components) != 0) || (bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) != 0) {
		upstreamBOMS = append(upstreamBOMS, normalize.FromCdxBom(&bom, artifactName, assetVersionName, origin))
	}

	for _, url := range externalURLs {
		slog.Info("found VEX external reference", "url", url)
		boms, _, invalid := s.artifactService.FetchBomsFromUpstream(artifactName, assetVersionName, externalURLs)
		if len(invalid) > 0 {
			slog.Warn("some VEX external references are invalid", "invalid", invalid)
		}
		if len(boms) > 0 {
			upstreamBOMS = append(upstreamBOMS, boms...)
		}
	}

	vulns, err := s.artifactService.SyncUpstreamBoms(upstreamBOMS, org, project, asset, assetVersion, artifact, userID)
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
	})

	return ctx.JSON(200, nil)
}

func (s *ScanController) DependencyVulnScan(c shared.Context, bom *cdx.BOM) (dtos.ScanResponse, error) {
	startTime := time.Now()
	defer func() {
		monitoring.DependencyVulnScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	scanResults := dtos.ScanResponse{} //Initialize empty struct to return when an error happens

	asset := shared.GetAsset(c)

	org := shared.GetOrg(c)
	project := shared.GetProject(c)

	userID := shared.GetSession(c).GetUserID()

	tag := c.Request().Header.Get("X-Tag")
	defaultBranch := c.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := c.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}
	artifactName := c.Request().Header.Get("X-Artifact-Name")
	origin := c.Request().Header.Get("X-Origin")
	normalized := normalize.FromCdxBom(bom, artifactName, assetVersionName, utils.OrDefault(utils.EmptyThenNil(origin), "DEFAULT"))

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
	wholeSBOM, err := s.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifactName, normalized, dtos.UpstreamStateInternal)
	if err != nil {
		slog.Error("could not update sbom", "err", err)
		return scanResults, err
	}

	opened, closed, newState, err := s.ScanNormalizedSBOM(org, project, asset, assetVersion, artifact, wholeSBOM, userID)
	if err != nil {
		slog.Error("could not scan normalized sbom", "err", err)
		return scanResults, err
	}

	return dtos.ScanResponse{
		AmountOpened:    opened,
		AmountClosed:    closed,
		DependencyVulns: utils.Map(newState, transformer.DependencyVulnToDTO),
	}, nil
}

func (s *ScanController) FirstPartyVulnScan(ctx shared.Context) error {
	startTime := time.Now()
	defer func() {
		monitoring.FirstPartyScanDuration.Observe(time.Since(startTime).Minutes())
	}()

	var sarifScan sarif.SarifSchema210Json

	defer ctx.Request().Body.Close()

	if err := ctx.Bind(&sarifScan); err != nil {
		return err
	}

	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)

	asset := shared.GetAsset(ctx)
	userID := shared.GetSession(ctx).GetUserID()

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

	return ctx.JSON(200, dtos.FirstPartyScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		FirstPartyVulns: utils.Map(newState, transformer.FirstPartyVulnToDto),
	})
}

func (s *ScanController) ScanDependencyVulnFromProject(c shared.Context) error {
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

func (s *ScanController) ScanSbomFile(c shared.Context) error {
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
