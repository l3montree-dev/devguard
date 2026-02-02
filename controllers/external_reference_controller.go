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

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type ExternalReferenceController struct {
	externalReferenceRepository shared.ExternalReferenceRepository
}

func NewExternalReferenceController(
	externalReferenceRepository shared.ExternalReferenceRepository,
) *ExternalReferenceController {
	return &ExternalReferenceController{
		externalReferenceRepository: externalReferenceRepository,
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
	URL  string `json:"url" validate:"required,url"`
	Type string `json:"type" validate:"required,oneof=vex sbom"`
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
			Type:             ref.Type,
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

	ref := models.ExternalReference{
		AssetID:          asset.ID,
		AssetVersionName: assetVersion.Name,
		URL:              req.URL,
		Type:             req.Type,
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
		Type:             ref.Type,
	})
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
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/external-references [delete]
func (c *ExternalReferenceController) DeleteForAssetVersion(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	if err := c.externalReferenceRepository.DeleteByAssetVersion(nil, asset.ID, assetVersion.Name); err != nil {
		slog.Error("failed to delete external references", "error", err)
		return echo.NewHTTPError(500, "failed to delete external references").WithInternal(err)
	}

	return ctx.NoContent(204)
}
