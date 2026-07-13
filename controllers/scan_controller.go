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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
// @Security BearerAuth
// @Param body body object true "CycloneDX VEX BOM"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Artifact-Name header string false "Artifact name"
// @Param X-Tag header string false "Tag flag"
// @Param X-Asset-Default-Branch header string false "Default branch"
// @Param X-Origin header string false "Origin"
// @Success 200
// @Router /vex [post]
// vexFormat identifies the serialization of an uploaded VEX document.
func (s ScanController) UploadVEX(ctx shared.Context) error {
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "ScanController.UploadVEX")
	defer span.End()

	body, err := io.ReadAll(ctx.Request().Body)
	ctx.Request().Body.Close()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "could not read request body").WithInternal(err)
	}

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

	span.SetAttributes(
		attribute.String("org.slug", org.Slug),
		attribute.String("project.slug", project.Slug),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersionName),
	)

	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(reqCtx, nil, assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
	if err := s.artifactService.SaveArtifact(reqCtx, nil, &artifact); err != nil {
		slog.Error("could not save artifact", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(500, "could not save artifact").WithInternal(err)
	}

	tx := s.assetVersionRepository.GetDB(reqCtx, nil).Begin()
	defer tx.Rollback()

	rules, format, err := s.VexRulesFromDocument(body, asset.ID, assetVersionName, origin)

	switch format {
	case dtos.ExternalReferenceTypeCycloneDX:
		var bom cdx.BOM
		if err := cdx.NewBOMDecoder(bytes.NewReader(body), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
			slog.Error("could not decode cyclonedx vex bom", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return echo.NewHTTPError(400, "could not decode vex file as CycloneDX BOM").WithInternal(err)
		}

		if err := s.vexRuleService.IngestVEXRules(reqCtx, tx, asset, assetVersion, rules); err != nil {
			tx.Rollback()
			slog.Error("could not ingest uploaded vex", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		// also ingest any VEX documents referenced by the uploaded BOM

		if err := s.ingestVexFromExternalReferences(reqCtx, tx, &bom, asset, assetVersion); err != nil {
			// swallow the error and log it, since the user has already uploaded a valid VEX document and we don't want to fail the request just because an external reference couldn't be fetched
			slog.Error("could not ingest vex from external references", "err", err)
		}
	case dtos.ExternalReferenceTypeOpenVEX, dtos.ExternalReferenceTypeCSAF:
		// CSAF and OpenVEX both ingest through the same rule pipeline; they only differ in
		// how the document is decoded into VEX rules.
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return echo.NewHTTPError(400, fmt.Sprintf("could not parse vex document: %v", err.Error())).WithInternal(err)
		}
		if err := s.vexRuleService.IngestVEXRules(reqCtx, tx, asset, assetVersion, rules); err != nil {
			tx.Rollback()
			slog.Error("could not ingest vex rules", "err", err, "format", format)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}

	tx.Commit()

	linkedCtx := trace.ContextWithSpan(context.Background(), trace.SpanFromContext(reqCtx))
	s.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := s.statisticsService.UpdateArtifactRiskAggregation(linkedCtx, nil, &artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	return ctx.JSON(200, nil)
}

// ingestVexFromExternalReferences looks for exploitability-statement (VEX) references in the
// SBOM's ExternalReferences, fetches the referenced VEX documents and ingests them as VEX rules.
func (s *ScanController) ingestVexFromExternalReferences(ctx context.Context, tx shared.DB, bom *cdx.BOM, asset models.Asset, assetVersion models.AssetVersion) error {
	externalURLs := []string{}
	if bom.ExternalReferences != nil {
		for _, ref := range *bom.ExternalReferences {
			if ref.Type == cdx.ERTypeExploitabilityStatement {
				externalURLs = append(externalURLs, ref.URL)
			}
		}
	}

	if len(externalURLs) == 0 {
		return nil
	}

	rules, valid, invalid := s.FetchVexFromUpstream(ctx, asset.ID, assetVersion.Name, externalURLs)

	if err := s.externalReferenceRepository.SaveBatch(ctx, tx, append(valid, invalid...)); err != nil {
		slog.Error("could not store vex external reference", "err", err)
	}

	if len(rules) == 0 {
		return nil
	}

	return s.vexRuleService.IngestVEXRules(ctx, tx, asset, assetVersion, rules)
}

func (s *ScanController) DependencyVulnScan(c shared.Context, bom *cdx.BOM) (opened, closed, newState []models.DependencyVuln, assetVersion models.AssetVersion, err error) {
	scanCtx, span := controllersTracer.Start(c.Request().Context(), "ScanController.DependencyVulnScan")
	defer span.End()

	var empty models.AssetVersion

	asset := shared.GetAsset(c)

	org := shared.GetOrg(c)
	project := shared.GetProject(c)

	userID := shared.GetSession(c).GetUserID()
	userAgent := c.Request().UserAgent()

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

	span.SetAttributes(
		attribute.String("org.slug", org.Slug),
		attribute.String("project.slug", project.Slug),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersionName),
		attribute.String("artifact.name", artifactName),
	)

	// check if we should keep the original root component
	keepOriginalSbomRootComponent := asset.KeepOriginalSbomRootComponent
	if c.Request().Header.Get("X-Keep-Original-SBOM-Root-Component") == "1" {
		keepOriginalSbomRootComponent = true
	} else if c.Request().Header.Get("X-Keep-Original-SBOM-Root-Component") == "0" {
		keepOriginalSbomRootComponent = false
	}
	// keepOriginalSbomRootComponent DOES NOT MAKE SENSE IF THE root component has no valid purl!
	if keepOriginalSbomRootComponent && (bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.PackageURL == "") {
		return nil, nil, nil, empty, echo.NewHTTPError(400, "supplied application as sbom source type is set, but the SBOM does not include a valid metadata.component.purl (root component PURL); keeping the original root requires a root component PURL")
	}

	normalized, normErr := normalize.SBOMGraphFromCycloneDX(bom, artifactName, utils.OrDefault(utils.EmptyThenNil(origin), "DEFAULT"), keepOriginalSbomRootComponent)
	if normErr != nil {
		span.RecordError(normErr)
		span.SetStatus(codes.Error, normErr.Error())
		return nil, nil, nil, empty, echo.NewHTTPError(400, fmt.Sprintf("Invalid SBOM: %s", normErr))
	}

	noWrite := c.Request().Header.Get("X-No-Write") == "1"

	// When noWrite, start a transaction early so that FindOrCreate is also rolled back.
	var earlyTx shared.DB
	findOrCreateTx := shared.DB(nil)
	if noWrite {
		earlyTx = s.assetVersionRepository.GetDB(scanCtx, nil).Begin()
		defer earlyTx.Rollback()
		findOrCreateTx = earlyTx
	}

	assetVersion, err = s.assetVersionRepository.FindOrCreate(scanCtx, findOrCreateTx, assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, empty, err
	}

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}

	// When noWrite, save the artifact within the early transaction so FK constraints are
	// satisfied; the deferred rollback ensures nothing is actually persisted.
	var artifactTx shared.DB
	if noWrite {
		artifactTx = earlyTx
	}
	if err = s.artifactService.SaveArtifact(scanCtx, artifactTx, &artifact); err != nil {
		slog.Error("could not save artifact", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, empty, err
	}

	// start a transaction for sbom updating AND scanning
	// when noWrite, reuse the early transaction so everything rolls back together
	var tx shared.DB
	if noWrite {
		tx = earlyTx
	} else {
		tx = s.assetVersionRepository.GetDB(scanCtx, nil).Begin()
		defer tx.Rollback()
	}

	wholeSBOM, err := s.assetVersionService.UpdateSBOM(scanCtx, tx, org, project, asset, assetVersion, artifactName, normalized)
	if err != nil {
		slog.Error("could not update sbom", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, empty, err
	}

	opened, closed, newState, err = s.ScanNormalizedSBOM(scanCtx, tx, org, project, asset, assetVersion, artifact, wholeSBOM, userID, &userAgent)
	if err != nil {
		slog.Error("could not scan normalized sbom", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, nil, empty, err
	}

	if !noWrite {
		if err := s.ingestVexFromExternalReferences(scanCtx, tx, bom, asset, assetVersion); err != nil {
			slog.Error("could not ingest vex from external references", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, nil, nil, empty, err
		}
	}

	if noWrite {
		// earlyTx deferred Rollback covers everything including FindOrCreate
	} else {
		tx.Commit()
	}

	span.SetAttributes(
		attribute.Int("scan.opened", len(opened)),
		attribute.Int("scan.closed", len(closed)),
		attribute.Int("scan.total", len(newState)),
	)

	if !noWrite {
		// detach from the HTTP request context (avoids cancellation on response) but keep the trace
		linkedCtx := trace.ContextWithSpan(context.Background(), span)

		// update the license information in the background
		s.FireAndForget(func() {
			slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
			_, err := s.componentService.GetAndSaveLicenseInformation(linkedCtx, nil, assetVersion, new(artifactName), false)
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
				if err = s.thirdPartyIntegration.HandleEvent(linkedCtx, shared.SBOMCreatedEvent{
					AssetVersion: shared.ToAssetVersionObject(assetVersion),
					Asset:        shared.ToAssetObject(asset),
					Project:      shared.ToProjectObject(project),
					Org:          shared.ToOrgObject(org),
					Artifact: shared.ArtifactObject{
						ArtifactName: artifactName,
					},
					SBOM: exportedBOM,
				}, &userAgent); err != nil {
					slog.Error("could not handle SBOM updated event", "err", err)
				} else {
					slog.Info("handled SBOM updated event", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
				}
			})
		}

		//Check if we want to create an issue for this assetVersion
		s.FireAndForget(func() {
			err := s.dependencyVulnService.SyncIssues(linkedCtx, org, project, asset, assetVersion, append(newState, closed...), &userAgent)
			if err != nil {
				slog.Error("could not create issues for vulnerabilities", "err", err)
			}
		})

		s.FireAndForget(func() {
			slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
			if err := s.statisticsService.UpdateArtifactRiskAggregation(linkedCtx, nil, &artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
			}
		})
	}

	return opened, closed, newState, assetVersion, nil
}

// @Summary Scan for first-party vulnerabilities
// @Deprecated Use /api/v2/sarif-scan instead.
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param body body object true "SARIF scan result"
// @Param X-Asset-Ref header string false "Asset version name"
// @Param X-Tag header string false "Tag flag"
// @Param X-Asset-Default-Branch header string false "Default branch"
// @Param X-Scanner header string true "Scanner ID"
// @Success 200 {object} dtos.FirstPartyScanResponse
// @Router /sarif-scan [post]
func (s *ScanController) FirstPartyVulnScan(ctx shared.Context) error {
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "ScanController.FirstPartyVulnScan")
	defer span.End()

	var sarifScan sarif.SarifSchema210Json

	var maxSize int64 = 16 * 1024 * 1024 //Max Upload Size 16mb

	ctx.Request().Body = http.MaxBytesReader(ctx.Response(), ctx.Request().Body, maxSize)
	defer ctx.Request().Body.Close()

	if err := ctx.Bind(&sarifScan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	span.SetAttributes(
		attribute.String("org.slug", org.Slug),
		attribute.String("project.slug", project.Slug),
		attribute.String("asset.slug", asset.Slug),
		attribute.String("assetVersion.name", assetVersionName),
	)

	assetVersion, err := s.assetVersionRepository.FindOrCreate(reqCtx, nil, assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return ctx.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	scannerID := ctx.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no X-Scanner header found")
		return ctx.JSON(400, map[string]string{
			"error": "no X-Scanner header found",
		})
	}

	span.SetAttributes(attribute.String("scanner.id", scannerID))

	userAgent := ctx.Request().UserAgent()

	// handle the scan result
	opened, closed, newState, err := s.HandleFirstPartyVulnResult(reqCtx, org, project, asset, &assetVersion, sarifScan, scannerID, userID, &userAgent)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return ctx.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	linkedCtx := trace.ContextWithSpan(context.Background(), span)

	s.FireAndForget(func() {
		err := s.firstPartyVulnService.SyncIssues(linkedCtx, org, project, asset, assetVersion, append(newState, closed...), &userAgent)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	err = s.assetVersionRepository.Save(reqCtx, nil, &assetVersion)
	if err != nil {
		slog.Error("could not save asset", "err", err)
	}

	span.SetAttributes(
		attribute.Int("scan.opened", len(opened)),
		attribute.Int("scan.closed", len(closed)),
		attribute.Int("scan.total", len(newState)),
	)

	return ctx.JSON(200, dtos.FirstPartyScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		FirstPartyVulns: utils.Map(newState, transformer.FirstPartyVulnToDto),
	})
}

// @Summary Scan for dependency vulnerabilities
// @Deprecated Use /api/v2/scan instead.
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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
	_, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanDependencyVulnFromProject")
	defer span.End()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	defer c.Request().Body.Close()
	if err := decoder.Decode(bom); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	opened, closed, vulns, _, err := s.DependencyVulnScan(c, bom)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return c.JSON(200, dtos.ScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		DependencyVulns: utils.Map(vulns, transformer.DependencyVulnToDTO),
	})
}

// @Summary Scan for dependency vulnerabilities without authentication (scan-only, results are not saved)
// @Deprecated Use /api/v2/scan-unauthenticated instead.
// @Tags Scanning
// @Param body body object true "CycloneDX SBOM"
// @Success 200 {object} dtos.ScanResponse
// @Router /scan-unauthenticated [post]
func (s *ScanController) ScanDependencyVulnUnauthenticated(c echo.Context) error {
	reqCtx, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanDependencyVulnUnauthenticated")
	defer span.End()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	defer c.Request().Body.Close()
	if err := decoder.Decode(bom); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	scanResults, err := s.ScanSBOMWithoutSaving(reqCtx, bom)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, fmt.Sprintf("could not do an unauthenticated scan: %s", err.Error())).WithInternal(err)
	}

	return c.JSON(200, scanResults)
}

// @Summary Scan for first-party vulnerabilities without authentication (scan-only, results are not saved)
// @Deprecated Use /api/v2/sarif-scan-unauthenticated instead.
// @Tags Scanning
// @Param body body object true "SARIF scan result"
// @Param X-Scanner header string true "Scanner ID"
// @Success 200 {object} dtos.FirstPartyScanResponse
// @Router /sarif-scan-unauthenticated [post]
func (s *ScanController) FirstPartyVulnScanUnauthenticated(c echo.Context) error {
	reqCtx, span := controllersTracer.Start(c.Request().Context(), "ScanController.FirstPartyVulnScanUnauthenticated")
	defer span.End()

	var sarifScan sarif.SarifSchema210Json

	var maxSize int64 = 16 * 1024 * 1024
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxSize)
	defer c.Request().Body.Close()

	if err := c.Bind(&sarifScan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SARIF format").WithInternal(err)
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		slog.Error("no X-Scanner header found")
		return echo.NewHTTPError(400, "no X-Scanner header found")
	}

	scanResults, err := s.ScanSarifWithoutSaving(reqCtx, sarifScan, scannerID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, fmt.Sprintf("could not do an unauthenticated sarif scan: %s", err.Error())).WithInternal(err)
	}

	return c.JSON(200, scanResults)
}

// @Summary Scan for dependency vulnerabilities without authentication, returns CycloneDX VEX
// @Tags Scanning
// @Param body body object true "CycloneDX SBOM"
// @Produce application/json
// @Success 200 {object} cyclonedx.BOM "CycloneDX VEX JSON"
// @Router /api/v2/scan-unauthenticated [post]
func (s *ScanController) ScanDependencyVulnUnauthenticatedVex(c echo.Context) error {
	reqCtx, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanDependencyVulnUnauthenticatedVex")
	defer span.End()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	defer c.Request().Body.Close()
	if err := decoder.Decode(bom); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	scanResults, err := s.ScanSBOMWithoutSaving(reqCtx, bom)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, fmt.Sprintf("could not do an unauthenticated scan: %s", err.Error())).WithInternal(err)
	}

	components := make([]cdx.Component, 0)
	compByPURL := map[string]string{} // purl -> bom-ref
	vulns := make([]cdx.Vulnerability, 0, len(scanResults.DependencyVulns))
	for _, v := range scanResults.DependencyVulns {
		vuln := cdx.Vulnerability{ID: v.CVEID}
		if v.CVE != nil && v.CVE.CVSS > 0 {
			score := float64(v.CVE.CVSS)
			vuln.Ratings = &[]cdx.VulnerabilityRating{{Score: &score, Method: cdx.ScoringMethodCVSSv31}}
		}
		if v.ComponentFixedVersion != nil {
			vuln.Recommendation = *v.ComponentFixedVersion
		}
		if v.ComponentPurl != "" {
			bomRef, exists := compByPURL[v.ComponentPurl]
			if !exists {
				bomRef = v.ComponentPurl
				comp := cdx.Component{
					BOMRef:     bomRef,
					PackageURL: v.ComponentPurl,
					Type:       cdx.ComponentTypeLibrary,
				}
				components = append(components, comp)
				compByPURL[v.ComponentPurl] = bomRef
			}
			vuln.Affects = &[]cdx.Affects{{Ref: bomRef}}
		}
		vulns = append(vulns, vuln)
	}

	vexBOM := cdx.NewBOM()
	vexBOM.Components = &components
	vexBOM.Vulnerabilities = &vulns

	c.Response().Header().Set("Content-Type", "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).SetEscapeHTML(false).Encode(vexBOM)
}

// @Summary Scan SARIF without authentication and return enriched SARIF
// @Tags Scanning
// @Param body body object true "SARIF scan result"
// @Param X-Scanner header string true "Scanner ID"
// @Produce application/json
// @Success 200 {object} object "Enriched SARIF JSON"
// @Router /api/v2/sarif-scan-unauthenticated [post]
func (s *ScanController) SarifScanUnauthenticated(c echo.Context) error {
	reqCtx, span := controllersTracer.Start(c.Request().Context(), "ScanController.SarifScanUnauthenticated")
	defer span.End()

	var sarifScan sarif.SarifSchema210Json

	var maxSize int64 = 16 * 1024 * 1024
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxSize)
	defer c.Request().Body.Close()

	if err := c.Bind(&sarifScan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SARIF format").WithInternal(err)
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		return echo.NewHTTPError(400, "no X-Scanner header found")
	}

	scanResults, err := s.ScanSarifWithoutSaving(reqCtx, sarifScan, scannerID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, fmt.Sprintf("could not do an unauthenticated sarif scan: %s", err.Error())).WithInternal(err)
	}

	vulns := utils.Map(scanResults.FirstPartyVulns, transformer.FirstPartyVulnDTOToModel)

	report := firstPartyVulnsToSARIF(scannerID, vulns)
	return c.JSON(200, report)
}

// @Summary Scan SBOM file
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param file formData file true "SBOM file"
// @Param X-Origin header string false "Origin"
// @Success 200 {object} dtos.ScanResponse
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/sbom-file [post]
func (s *ScanController) ScanSbomFile(c shared.Context) error {
	_, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanSbomFile")
	defer span.End()

	var maxSize int64 = 16 * 1024 * 1024 //Max Upload Size 16mb
	err := c.Request().ParseMultipartForm(maxSize)
	if err != nil {
		slog.Error("error when parsing data")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	file, _, err := c.Request().FormFile("file")
	if err != nil {
		slog.Error("error when forming file")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer file.Close()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(file, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	// if no origin is provided via header set it ourselves
	origin := c.Request().Header.Get("X-Origin")
	if origin == "" {
		origin = "sbom-file-upload"
		c.Request().Header.Set("X-Origin", origin)
	}

	opened, closed, vulns, _, err := s.DependencyVulnScan(c, bom)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return c.JSON(200, dtos.ScanResponse{
		AmountOpened:    len(opened),
		AmountClosed:    len(closed),
		DependencyVulns: utils.Map(vulns, transformer.DependencyVulnToDTO),
	})

}

// @Summary Scan SBOM file and return CycloneDX VEX
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param body body cyclonedx.BOM true "CycloneDX SBOM"
// @Produce application/json
// @Success 200 {object} cyclonedx.BOM "CycloneDX VEX JSON"
// @Router /api/v2/scan [post]
func (s *ScanController) ScanSbomFileVex(c shared.Context) error {
	_, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanSbomFileVex")
	defer span.End()

	bom := new(cdx.BOM)
	defer c.Request().Body.Close()
	if err := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return echo.NewHTTPError(400, "Invalid SBOM format").WithInternal(err)
	}

	origin := c.Request().Header.Get("X-Origin")
	if origin == "" {
		c.Request().Header.Set("X-Origin", "sbom-file-upload")
	}

	_, _, vulns, assetVersion, err := s.DependencyVulnScan(c, bom)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	asset := shared.GetAsset(c)

	vexBOM := s.assetVersionService.BuildVeX(c.Request().Context(), nil, normalize.BOMMetadata{}, asset, assetVersion, vulns)

	c.Response().Header().Set("Content-Type", "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).SetEscapeHTML(false).Encode(vexBOM)
}

// @Summary Scan SARIF file and return enriched SARIF
// @Tags Scanning
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param body body object true "SARIF scan result"
// @Produce application/json
// @Success 200 {object} object "Enriched SARIF JSON"
// @Router /api/v2/sarif-scan [post]
func (s *ScanController) ScanSarifFile(c shared.Context) error {
	_, span := controllersTracer.Start(c.Request().Context(), "ScanController.ScanSarifFile")
	defer span.End()

	var sarifScan sarif.SarifSchema210Json

	var maxSize int64 = 16 * 1024 * 1024
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxSize)
	defer c.Request().Body.Close()

	if err := c.Bind(&sarifScan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	org := shared.GetOrg(c)
	project := shared.GetProject(c)
	asset := shared.GetAsset(c)
	userID := shared.GetSession(c).GetUserID()

	tag := c.Request().Header.Get("X-Tag")
	defaultBranch := c.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := c.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
		defaultBranch = "main"
	}

	assetVersion, err := s.assetVersionRepository.FindOrCreate(c.Request().Context(), nil, assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return c.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		return c.JSON(400, map[string]string{"error": "no X-Scanner header found"})
	}

	userAgent := c.Request().UserAgent()

	noWrite := c.Request().Header.Get("X-No-Write") == "1"

	var newState []models.FirstPartyVuln
	if noWrite {
		// When noWrite, scan without persisting anything to the database.
		scanResults, scanErr := s.ScanSarifWithoutSaving(c.Request().Context(), sarifScan, scannerID)
		if scanErr != nil {
			slog.Error("could not scan sarif without saving", "err", scanErr)
			span.RecordError(scanErr)
			span.SetStatus(codes.Error, scanErr.Error())
			return c.JSON(500, map[string]string{"error": "could not handle scan result"})
		}
		newState = utils.Map(scanResults.FirstPartyVulns, transformer.FirstPartyVulnDTOToModel)
	} else {
		_, _, newState, err = s.HandleFirstPartyVulnResult(c.Request().Context(), org, project, asset, &assetVersion, sarifScan, scannerID, userID, &userAgent)
		if err != nil {
			slog.Error("could not handle scan result", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return c.JSON(500, map[string]string{"error": "could not handle scan result"})
		}
		linkedCtx := trace.ContextWithSpan(context.Background(), span)
		s.FireAndForget(func() {
			if err := s.firstPartyVulnService.SyncIssues(linkedCtx, org, project, asset, assetVersion, newState, &userAgent); err != nil {
				slog.Error("could not create issues for vulnerabilities", "err", err)
			}
		})
		if err := s.assetVersionRepository.Save(c.Request().Context(), nil, &assetVersion); err != nil {
			slog.Error("could not save asset", "err", err)
		}
	}

	report := firstPartyVulnsToSARIF(scannerID, newState)
	c.Response().Header().Set("Content-Type", "application/json")
	return c.JSON(200, report)
}

func firstPartyVulnsToSARIF(scannerID string, vulns []models.FirstPartyVuln) sarif.SarifSchema210Json {
	report := sarif.SarifSchema210Json{
		Version: "2.1.0",
		Schema:  new("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/123e95847b13fbdd4cbe2120fa5e33355d4a042b/Schemata/sarif-schema-2.1.0.json"),
		Runs:    make([]sarif.Run, 0),
	}

	run := sarif.Run{
		Tool: sarif.Tool{
			Driver: sarif.ToolComponent{
				Name:  scannerID,
				Rules: make([]sarif.ReportingDescriptor, 0),
			},
		},
		Results: make([]sarif.Result, 0),
	}

	addedRuleIDs := make(map[string]bool)
	for _, vuln := range vulns {
		if _, exists := addedRuleIDs[vuln.RuleID]; !exists {
			rule := sarif.ReportingDescriptor{
				ID:               vuln.RuleID,
				Name:             &vuln.RuleName,
				FullDescription:  &sarif.MultiformatMessageString{Text: vuln.RuleDescription},
				Help:             &sarif.MultiformatMessageString{Text: vuln.RuleHelp},
				HelpURI:          &vuln.RuleHelpURI,
				ShortDescription: &sarif.MultiformatMessageString{Text: vuln.RuleName},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: vuln.RuleProperties,
				},
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			addedRuleIDs[vuln.RuleID] = true
		}

		result := sarif.Result{
			RuleID: &vuln.RuleID,
			Message: sarif.Message{
				Text: vuln.RuleDescription,
			},
		}

		snippet, err := transformer.FromJSONSnippetContents(vuln)
		if err != nil {
			slog.Error("could not marshal snippet contents", "err", err)
		} else {
			locations := make([]sarif.Location, 0, len(snippet.Snippets))
			for _, sc := range snippet.Snippets {
				locations = append(locations, sarif.Location{
					PhysicalLocation: sarif.PhysicalLocation{
						ArtifactLocation: sarif.ArtifactLocation{URI: &vuln.URI},
						Region: &sarif.Region{
							StartLine:   &sc.StartLine,
							StartColumn: &sc.StartColumn,
							EndLine:     &sc.EndLine,
							EndColumn:   &sc.EndColumn,
							Snippet:     &sarif.ArtifactContent{Text: &sc.Snippet},
						},
					},
				})
			}
			result.Locations = append(result.Locations, locations...)
		}

		if vuln.State != "open" {
			justification := string(vuln.State)
			result.Suppressions = []sarif.Suppression{{
				Kind:          sarif.SuppressionKind("inSource"),
				Justification: &justification,
			}}
		}

		run.Results = append(run.Results, result)
	}

	report.Runs = append(report.Runs, run)
	return report
}
