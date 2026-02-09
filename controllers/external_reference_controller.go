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
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
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

type ExternalReferenceDTO struct {
	ID               string `json:"id"`
	AssetID          string `json:"assetId"`
	AssetVersionName string `json:"assetVersionName"`
	URL              string `json:"url"`
	Type             string `json:"type"`
}

type CreateExternalReferenceRequest struct {
	URL              string `json:"url" validate:"required,url"`
	Type             string `json:"type" validate:"required,oneof=cyclonedxvex csaf"`
	CSAFPackageScope string `json:"csafPackageScope"` // only relevant for csaf references - NEEDS TO BE A VALID PURL
}

// @Summary List external references for an asset version
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {array} ExternalReferenceDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references [get]
func (c *ExternalReferenceController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	refs, err := c.externalReferenceRepository.FindByAssetVersion(nil, asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("failed to list external references", "error", err)
		return echo.NewHTTPError(500, "failed to list external references").WithInternal(err)
	}

	result := make([]ExternalReferenceDTO, len(refs))
	for i, ref := range refs {
		result[i] = ExternalReferenceDTO{
			ID:               ref.ID.String(),
			AssetID:          ref.AssetID.String(),
			AssetVersionName: ref.AssetVersionName,
			URL:              ref.URL,
			Type:             string(ref.Type),
		}
	}

	return ctx.JSON(200, result)
}

// @Summary Create an external reference
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
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

	var req CreateExternalReferenceRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	// validate
	if err := shared.V.Struct(req); err != nil {
		return err
	}

	if req.Type == "csaf" {
		if req.CSAFPackageScope == "" {
			return echo.NewHTTPError(400, "csafPackageScope is required for csaf references")
		}
		if _, err := packageurl.FromString(req.CSAFPackageScope); err != nil {
			return echo.NewHTTPError(400, "csafPackageScope must be a valid PURL").WithInternal(err)
		}
	}

	var refType models.ExternalReferenceType
	switch req.Type {
	case "cyclonedxvex":
		refType = models.ExternalReferenceTypeCycloneDxVEX
	case "csaf":
		refType = models.ExternalReferenceTypeCSAF
	default:
		return echo.NewHTTPError(400, "invalid external reference type")
	}

	ref := models.ExternalReference{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		URL:              req.URL,
		Type:             refType,
		CSAFPackageScope: req.CSAFPackageScope,
	}

	if err := c.externalReferenceRepository.Create(nil, &ref); err != nil {
		slog.Error("failed to create external reference", "error", err)
		return echo.NewHTTPError(500, "failed to create external reference").WithInternal(err)
	}

	return ctx.JSON(201, ExternalReferenceDTO{
		ID:               ref.ID.String(),
		AssetID:          ref.AssetID.String(),
		AssetVersionName: ref.AssetVersionName,
		URL:              ref.URL,
		Type:             string(ref.Type),
	})
}

// @Summary Sync external sources for all artifacts of an asset version
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
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
	userID := shared.GetSession(ctx).GetUserID()

	artifacts, err := c.artifactRepository.GetByAssetIDAndAssetVersionName(asset.ID, assetVersion.Name)
	if err != nil {
		slog.Error("could not get artifacts for asset version", "err", err)
		return echo.NewHTTPError(500, "could not get artifacts for asset version").WithInternal(err)
	}

	for _, artifact := range artifacts {
		tx := c.artifactRepository.Begin()

		_, _, vulns, err := c.RunArtifactSecurityLifecycle(tx, org, project, asset, assetVersion, artifact, userID)
		if err != nil {
			tx.Rollback()
			slog.Error("could not scan sbom after syncing external sources", "err", err, "artifact", artifact.ArtifactName)
			return echo.NewHTTPError(500, "could not scan sbom after syncing external sources").WithInternal(err)
		}

		commitResult := tx.Commit()
		if commitResult.Error != nil {
			slog.Error("could not commit transaction after syncing external sources", "err", commitResult.Error, "artifact", artifact.ArtifactName)
			return echo.NewHTTPError(500, "could not persist scan results after syncing external sources").WithInternal(commitResult.Error)
		}

		c.FireAndForget(func() {
			if err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns); err != nil {
				slog.Error("could not create issues for vulnerabilities", "err", err)
			}
		})

		c.FireAndForget(func() {
			slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
			if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
			}
		})
	}

	return ctx.NoContent(200)
}

// @Summary Delete all external references for an asset version
// @Tags ExternalReferences
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references/{id} [delete]
func (c *ExternalReferenceController) Delete(ctx shared.Context) error {
	id := ctx.Param("id")
	// parse to uuid
	uuidID, err := uuid.Parse(id)
	if err != nil {
		return echo.NewHTTPError(400, "invalid external reference ID").WithInternal(err)
	}

	if err := c.externalReferenceRepository.Delete(nil, uuidID); err != nil {
		slog.Error("failed to delete external reference", "error", err)
		return echo.NewHTTPError(500, "failed to delete external reference").WithInternal(err)
	}

	return ctx.NoContent(204)
}
