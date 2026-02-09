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
	"fmt"
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
	assetVersionRepository      shared.AssetVersionRepository
	assetVersionService         shared.AssetVersionService
	statisticsService           shared.StatisticsService
	artifactService             shared.ArtifactService
	dependencyVulnService       shared.DependencyVulnService
	firstPartyVulnService       shared.FirstPartyVulnService
	vexRuleService              shared.VEXRuleService
	externalReferenceRepository shared.ExternalReferenceRepository
	componentService            shared.ComponentService
	thirdPartyIntegration       shared.IntegrationAggregate
	shared.ScanService
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
}

func NewScanController(scanService shared.ScanService, assetVersionRepository shared.AssetVersionRepository, assetVersionService shared.AssetVersionService, statisticsService shared.StatisticsService, dependencyVulnService shared.DependencyVulnService, firstPartyVulnService shared.FirstPartyVulnService, artifactService shared.ArtifactService, dependencyVulnRepository shared.DependencyVulnRepository, synchronizer utils.FireAndForgetSynchronizer, vexRuleService shared.VEXRuleService, externalReferenceRepository shared.ExternalReferenceRepository, componentService shared.ComponentService, thirdPartyIntegration shared.IntegrationAggregate) *ScanController {
	return &ScanController{
		assetVersionService:         assetVersionService,
		assetVersionRepository:      assetVersionRepository,
		statisticsService:           statisticsService,
		dependencyVulnService:       dependencyVulnService,
		firstPartyVulnService:       firstPartyVulnService,
		FireAndForgetSynchronizer:   synchronizer,
		artifactService:             artifactService,
		ScanService:                 scanService,
		vexRuleService:              vexRuleService,
		externalReferenceRepository: externalReferenceRepository,
		componentService:            componentService,
		thirdPartyIntegration:       thirdPartyIntegration,
	}
}

// @Summary Upload VEX document
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "CycloneDX VEX BOM"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Artifact-Name header string false "Artifact name"
// @Param X-Tag header string false "Tag flag"
// @Param X-Asset-Default-Branch header string false "Default branch"
// @Param X-Origin header string false "Origin"
// @Success 200
// @Router /vex [post]
func (s ScanController) UploadVEX(ctx shared.Context) error {
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(ctx.Request().Body, cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		slog.Error("could not decode cyclonedx vex bom", "err", err)
		return echo.NewHTTPError(400, "could not decode vex file as CycloneDX BOM").WithInternal(err)
	}

	ctx.Request().Body.Close()

	asset := shared.GetAsset(ctx)
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

	tx := s.assetVersionRepository.GetDB(nil).Begin()

	refs := []models.ExternalReference{}
	// store the external references from VEX upload
	for _, url := range externalURLs {
		// can only be cyclonedx since we are parsing them from the cyclonedx bom
		ref := models.ExternalReference{
			AssetID:          asset.ID,
			AssetVersionName: assetVersionName,
			URL:              url,
			Type:             "cyclonedx",
		}
		if err := s.externalReferenceRepository.Create(tx, &ref); err != nil {
			slog.Error("could not store vex external reference", "err", err, "url", url)
		}
		refs = append(refs, ref)
	}

	vexReport, err := normalize.NewVexReport(&bom, origin)
	if err != nil {
		slog.Error("could not create vex report from bom", "err", err)
		return echo.NewHTTPError(400, fmt.Sprintf("Invalid VEX BOM format: %s", err)).WithInternal(err)
	}

	vexReports := []*normalize.VexReport{}
	// check if there are components or vulnerabilities in the bom
	vexReports = append(vexReports, vexReport)

	for _, url := range externalURLs {
		slog.Info("found VEX external reference", "url", url)
		fetchedVexReports, _, invalid := s.FetchVexFromUpstream(refs)
		if len(invalid) > 0 {
			slog.Warn("some VEX external references are invalid", "invalid", invalid)
		}

		if len(fetchedVexReports) > 0 {
			vexReports = append(vexReports, fetchedVexReports...)
		}
	}

	if len(vexReports) > 0 {
		// process the vex
		if err := s.vexRuleService.IngestVexes(tx, asset, assetVersion, vexReports); err != nil {
			tx.Rollback()
			slog.Error("could not ingest vex reports", "err", err)
			return err
		}
	}

	tx.Commit()

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

	// Generate default artifact name BEFORE creating the SBOM graph
	if artifactName == "" {
		artifactName = normalize.ArtifactPurl(c.Request().Header.Get("X-Scanner"), org.Slug+"/"+project.Slug+"/"+asset.Slug)
	}

	// check if we should keep the original root component
	keepOriginalSbomRootComponent := asset.KeepOriginalSbomRootComponent
	if c.Request().Header.Get("X-Keep-Original-SBOM-Root-Component") == "1" {
		keepOriginalSbomRootComponent = true
	} else if c.Request().Header.Get("X-Keep-Original-SBOM-Root-Component") == "0" {
		keepOriginalSbomRootComponent = false
	}
	// keepOriginalSbomRootComponent DOES NOT MAKE SENSE IF THE root component has no valid purl!
	if keepOriginalSbomRootComponent && (bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.PackageURL == "") {
		return scanResults, echo.NewHTTPError(400, "keepOriginalSbomRootComponent is set, but the SBOM does not include a valid metadata.component.purl (root component PURL); keeping the original root requires a root component PURL")
	}

	normalized, err := normalize.SBOMGraphFromCycloneDX(bom, artifactName, utils.OrDefault(utils.EmptyThenNil(origin), "DEFAULT"), keepOriginalSbomRootComponent)
	if err != nil {
		return scanResults, echo.NewHTTPError(400, fmt.Sprintf("Invalid SBOM: %s", err))
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return scanResults, err
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
	// start a transaction for sbom updating AND scanning
	tx := s.assetVersionRepository.GetDB(nil).Begin()
	wholeSBOM, err := s.assetVersionService.UpdateSBOM(tx, org, project, asset, assetVersion, artifactName, normalized)
	if err != nil {
		tx.Rollback()
		slog.Error("could not update sbom", "err", err)
		return scanResults, err
	}

	opened, closed, newState, err := s.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, wholeSBOM, userID)
	if err != nil {
		tx.Rollback()
		slog.Error("could not scan normalized sbom", "err", err)
		return scanResults, err
	}

	tx.Commit()

	// update the license information in the background
	s.FireAndForget(func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		_, err := s.componentService.GetAndSaveLicenseInformation(nil, assetVersion, utils.Ptr(artifactName), false)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	})

	if assetVersion.DefaultBranch || assetVersion.Type == models.AssetVersionTag {
		s.FireAndForget(func() {
			// Export the updated graph back to CycloneDX format for the event
			exportedBOM := wholeSBOM.ToCycloneDX(normalize.BOMMetadata{
				RootName: artifactName,
			})
			if err = s.thirdPartyIntegration.HandleEvent(shared.SBOMCreatedEvent{
				AssetVersion: shared.ToAssetVersionObject(assetVersion),
				Asset:        shared.ToAssetObject(asset),
				Project:      shared.ToProjectObject(project),
				Org:          shared.ToOrgObject(org),
				Artifact: shared.ArtifactObject{
					ArtifactName: artifactName,
				},
				SBOM: exportedBOM,
			}); err != nil {
				slog.Error("could not handle SBOM updated event", "err", err)
			} else {
				slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
			}
		})
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
	})

	return dtos.ScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		DependencyVulns: utils.Map(newState, transformer.DependencyVulnToDTO),
	}, nil
}

// @Summary Scan for first-party vulnerabilities
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "SARIF scan result"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Tag header string false "Tag flag"
// @Param X-Asset-Default-Branch header string false "Default branch"
// @Param X-Scanner header string true "Scanner ID"
// @Success 200 {object} dtos.FirstPartyScanResponse
// @Router /sarif-scan [post]
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
	opened, closed, newState, err := s.HandleFirstPartyVulnResult(org, project, asset, &assetVersion, sarifScan, scannerID, userID)
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

// @Summary Scan for dependency vulnerabilities
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Param body body object true "CycloneDX SBOM"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Artifact-Name header string false "Artifact name"
// @Param X-Tag header string false "Tag flag"
// @Param X-Asset-Default-Branch header string false "Default branch"
// @Param X-Origin header string false "Origin"
// @Param X-Scanner header string false "Scanner ID"
// @Success 200 {object} dtos.ScanResponse
// @Router /scan [post]
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

// @Summary Scan SBOM file
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Param file formData file true "SBOM file"
// @Param X-Origin header string false "Origin"
// @Success 200 {object} dtos.ScanResponse
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/sbom-file [post]
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
