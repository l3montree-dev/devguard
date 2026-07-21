// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package controllers

import (
	"context"
	"log/slog"
	neturl "net/url"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ExternalReferenceController struct {
	externalReferenceRepository shared.ExternalReferenceRepository
	artifactRepository          shared.ArtifactRepository
	dependencyVulnService       shared.DependencyVulnService
	statisticsService           shared.StatisticsService
	utils.FireAndForgetSynchronizer
	shared.ScanService
}

func NewExternalReferenceController(
	externalReferenceRepository shared.ExternalReferenceRepository,
	artifactRepository shared.ArtifactRepository,
	dependencyVulnService shared.DependencyVulnService,
	statisticsService shared.StatisticsService,
	synchronizer utils.FireAndForgetSynchronizer,
	scanService shared.ScanService,
) *ExternalReferenceController {
	return &ExternalReferenceController{
		externalReferenceRepository: externalReferenceRepository,
		artifactRepository:          artifactRepository,
		dependencyVulnService:       dependencyVulnService,
		statisticsService:           statisticsService,
		FireAndForgetSynchronizer:   synchronizer,
		ScanService:                 scanService,
	}
}

// @Summary List external references for an asset version
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {array} ExternalReferenceDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references [get]
func (c *ExternalReferenceController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	refs, err := c.externalReferenceRepository.FindByAssetVersion(ctx.Request().Context(), nil, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to list external references", "error", err)
		return echo.NewHTTPError(500, "failed to list external references").WithInternal(err)
	}

	result := make([]dtos.ExternalReferenceDTO, len(refs))
	for i, ref := range refs {
		result[i] = dtos.ExternalReferenceDTO{
			AssetID:          ref.AssetID.String(),
			AssetVersionName: ref.AssetVersionName,
			URL:              ref.URL,
			Type:             ref.Type,
		}
	}

	return ctx.JSON(200, result)
}

// @Summary Create an external reference
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param request body CreateExternalReferenceRequest true "Create request"
// @Success 201 {object} ExternalReferenceDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references [post]
func (c *ExternalReferenceController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	var req dtos.CreateExternalReferenceRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	// validate
	if err := dtos.V.Struct(req); err != nil {
		return err
	}

	ref := models.ExternalReference{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		URL:              req.URL,
		Type:             req.Type, // already validated by struct tags
	}

	if err := c.externalReferenceRepository.Create(ctx.Request().Context(), nil, &ref); err != nil {
		slog.Error("failed to create external reference", "error", err)
		return echo.NewHTTPError(500, "failed to create external reference").WithInternal(err)
	}

	return ctx.JSON(201, dtos.ExternalReferenceDTO{
		AssetID:          ref.AssetID.String(),
		AssetVersionName: ref.AssetVersionName,
		URL:              ref.URL,
		Type:             ref.Type,
	})
}

func (c *ExternalReferenceController) syncArtifact(reqCtx context.Context, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, ownerID string, userAgent string) error {
	tx := c.artifactRepository.Begin(reqCtx)
	defer tx.Rollback()

	_, _, vulns, err := c.RunArtifactSecurityLifecycle(reqCtx, tx, org, project, asset, assetVersion, artifact, ownerID, &userAgent)
	if err != nil {
		tx.Rollback()
		slog.Error("could not scan sbom after syncing external sources", "err", err, "artifact", artifact.ArtifactName)
		return echo.NewHTTPError(500, "could not scan sbom after syncing external sources").WithInternal(err)
	}

	if commitResult := tx.Commit(); commitResult.Error != nil {
		slog.Error("could not commit transaction after syncing external sources", "err", commitResult.Error, "artifact", artifact.ArtifactName)
		return echo.NewHTTPError(500, "could not persist scan results after syncing external sources").WithInternal(commitResult.Error)
	}

	linkedCtx := trace.ContextWithSpan(context.Background(), trace.SpanFromContext(reqCtx))
	c.FireAndForget(func() {
		if err := c.dependencyVulnService.SyncIssues(linkedCtx, org, project, asset, assetVersion, vulns, &userAgent); err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})
	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(linkedCtx, nil, &artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	return nil
}

// @Summary Sync external sources for all artifacts of an asset version
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references/sync [post]
func (c *ExternalReferenceController) Sync(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	ownerID := shared.GetSession(ctx).GetOwnerID()
	userAgent := ctx.Request().UserAgent()

	artifacts, err := c.artifactRepository.GetByAssetIDAndAssetVersionName(ctx.Request().Context(), nil, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("could not get artifacts for asset version", "err", err)
		return echo.NewHTTPError(500, "could not get artifacts for asset version").WithInternal(err)
	}

	for _, artifact := range artifacts {
		if err := c.syncArtifact(ctx.Request().Context(), org, project, asset, assetVersion, artifact, ownerID, userAgent); err != nil {
			return err
		}
	}

	return ctx.NoContent(200)
}

// @Summary Sync external sources for a single artifact
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/sync-external-sources/ [post]
func (c *ExternalReferenceController) SyncArtifact(ctx shared.Context) error {
	if err := c.syncArtifact(ctx.Request().Context(), shared.GetOrg(ctx), shared.GetProject(ctx), shared.GetAsset(ctx), shared.GetAssetVersion(ctx), shared.GetArtifact(ctx), shared.GetSession(ctx).GetOwnerID(), ctx.Request().UserAgent()); err != nil {
		return err
	}
	return ctx.NoContent(200)
}

// @Summary Delete an external reference by URL
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param url path string true "URL-encoded external reference URL"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references/{url} [delete]
func (c *ExternalReferenceController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	encodedURL := ctx.Param("url")
	url, err := neturl.QueryUnescape(encodedURL)
	if err != nil {
		return echo.NewHTTPError(400, "invalid url path parameter").WithInternal(err)
	}

	if err := c.externalReferenceRepository.DeleteByURL(ctx.Request().Context(), nil, asset.ID, assetVersion.Name, url); err != nil {
		slog.Error("failed to delete external reference", "error", err)
		return echo.NewHTTPError(500, "failed to delete external reference").WithInternal(err)
	}

	return ctx.NoContent(204)
}
