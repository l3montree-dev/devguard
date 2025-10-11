// Copyright (C) 2025 l3montree GmbH
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

package api

import (
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

// all middlewares which modify the current request context and fetch some data from the database

// this middleware is used to set the project slug parameter based on an X-Asset-ID header.
// it is useful for reusing the projectAccessControl middleware and rely on the rbac to determine if the user has access to an specific asset
func assetNameMiddleware() core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// extract the asset id from the header
			// asset name is <organization_slug>/<project_slug>/<asset_slug>
			assetName := ctx.Request().Header.Get("X-Asset-Name")
			if assetName == "" {
				return echo.NewHTTPError(400, "no X-Asset-Name header provided")
			}
			// split the asset name
			assetParts := strings.Split(assetName, "/")
			if len(assetParts) == 5 {
				// the user probably provided the full url
				// check if projects and assets is part of the asset parts - if so, remove them
				// <organization>/projects/<project>/assets/<asset>
				if assetParts[1] == "projects" && assetParts[3] == "assets" {
					assetParts = []string{assetParts[0], assetParts[2], assetParts[4]}
				}
			}
			if len(assetParts) != 3 {
				return echo.NewHTTPError(400, "invalid asset name")
			}
			// set the project slug
			ctx.Set("projectSlug", assetParts[1])
			ctx.Set("organization", assetParts[0])
			ctx.Set("assetSlug", assetParts[2])
			return next(ctx)
		}
	}
}

func artifactMiddleware(repository core.ArtifactRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			assetVersion := core.GetAssetVersion(ctx)

			artifactName, err := core.GetArtifactName(ctx)
			if err != nil {
				slog.Error("invalid artifact name", "err", err)
				return echo.NewHTTPError(400, "invalid artifact name")
			}

			artifact, err := repository.ReadArtifact(artifactName, assetVersion.Name, assetVersion.AssetID)

			if err != nil {
				return echo.NewHTTPError(404, "could not find artifact").WithInternal(err)
			}

			core.SetArtifact(ctx, artifact)

			return next(ctx)
		}
	}
}

func assetVersionMiddleware(repository core.AssetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {

			asset := core.GetAsset(ctx)

			assetVersionSlug, err := core.GetAssetVersionSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset version slug")
			}

			assetVersion, err := repository.ReadBySlug(asset.GetID(), assetVersionSlug)

			if err != nil {
				if assetVersionSlug == "default" {
					core.SetAssetVersion(ctx, models.AssetVersion{})

					return next(ctx)
				}
				return echo.NewHTTPError(404, "could not find asset version")
			}

			core.SetAssetVersion(ctx, assetVersion)

			// Update LastAccessedAt in a goroutine to avoid blocking the request
			go func() {
				now := time.Now()
				assetVersion.LastAccessedAt = now
				// Use nil for tx to use the default database connection
				if err := repository.Save(nil, &assetVersion); err != nil {
					slog.Error("failed to update LastAccessedAt", "error", err, "assetVersion", assetVersion.Name)
				}
			}()

			return next(ctx)
		}
	}
}
