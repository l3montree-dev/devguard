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

package middlewares

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// all middlewares which modify the current request context and fetch some data from the database

// this middleware is used to set the project slug parameter based on an X-Asset-ID header.
// it is useful for reusing the projectAccessControl middleware and rely on the rbac to determine if the user has access to an specific asset
func AssetNameMiddleware() shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			// extract the asset id from the header
			// asset name is <organization_slug>/<project_slug>/<asset_slug>
			assetName := ctx.Request().Header.Get("X-Asset-Name")
			if assetName == "" {
				return echo.NewHTTPError(400, "no X-Asset-Name header provided")
			}
			var err error
			assetName, err = normalize.AssetName(assetName)
			if err != nil {
				slog.Error("invalid asset name", "err", err)
				return echo.NewHTTPError(400, "invalid asset name")
			}

			assetParts := strings.Split(assetName, "/")
			// set the project slug
			shared.SetProjectSlug(ctx, assetParts[1])
			shared.SetOrgSlug(ctx, assetParts[0])
			shared.SetAssetSlug(ctx, assetParts[2])
			return next(ctx)
		}
	}
}

func ArtifactMiddleware(repository shared.ArtifactRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			assetVersion := shared.GetAssetVersion(ctx)

			artifactName, err := shared.GetArtifactName(ctx)
			if err != nil {
				slog.Error("invalid artifact name", "err", err)
				return echo.NewHTTPError(400, "invalid artifact name")
			}

			artifact, err := repository.ReadArtifact(ctx.Request().Context(), nil, artifactName, assetVersion.ID)

			if err != nil {
				return echo.NewHTTPError(404, "could not find artifact").WithInternal(err)
			}

			shared.SetArtifact(ctx, artifact)

			return next(ctx)
		}
	}
}

// ArtifactQueryMiddleware resolves the optional artifactName query parameter to the artifact of the asset version
func ArtifactQueryMiddleware(repository shared.ArtifactRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			artifactName := ctx.QueryParam("artifactName")
			if artifactName == "" {
				return next(ctx)
			}

			assetVersion := shared.GetAssetVersion(ctx)
			artifact, err := repository.ReadArtifact(ctx.Request().Context(), nil, artifactName, assetVersion.ID)
			if err != nil {
				if !shared.IsNotFound(err) {
					return echo.NewHTTPError(500, "could not read artifact").WithInternal(err)
				}
				// an unknown artifact still answers with empty results, its nil id matches nothing
				artifact = models.Artifact{ArtifactName: artifactName, AssetVersionID: assetVersion.ID, AssetID: assetVersion.AssetID}
			}

			shared.SetArtifact(ctx, artifact)

			return next(ctx)
		}
	}
}

func AssetVersionMiddleware(repository shared.AssetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {

			asset := shared.GetAsset(ctx)

			assetVersionSlugOrName, err := shared.GetAssetVersionSlugOrName(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset version slug")
			}

			assetVersion, err := readAssetVersionBySlugOrName(ctx.Request().Context(), repository, asset.GetID(), assetVersionSlugOrName)

			if err != nil {
				if assetVersionSlugOrName == "default" {
					shared.SetAssetVersion(ctx, models.AssetVersion{})

					return next(ctx)
				}
				return echo.NewHTTPError(404, "could not find asset version")
			}

			shared.SetAssetVersion(ctx, assetVersion)

			return next(ctx)
		}
	}
}

func readAssetVersionBySlugOrName(ctx context.Context, repository shared.AssetVersionRepository, assetID uuid.UUID, ref string) (models.AssetVersion, error) {
	assetVersion, err := repository.ReadBySlug(ctx, nil, assetID, ref)
	if err == nil {
		return assetVersion, nil
	}

	name, unescapeErr := url.PathUnescape(ref)
	if unescapeErr != nil {
		return assetVersion, err
	}

	return repository.ReadByName(ctx, nil, name, assetID)
}

func ScanMiddleware(assetVersionRepository shared.AssetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {

			asset := shared.GetAsset(ctx)
			assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
			if assetVersionName == "" {
				return echo.NewHTTPError(400, "no X-Asset-Ref header provided")
			}
			assetVersion, err := assetVersionRepository.ReadByName(ctx.Request().Context(), nil, assetVersionName, asset.ID)
			if err != nil {
				// if the asset version is not found, we do not return an error here, because the asset version might not exist yet
				return next(ctx)
			}

			shared.SetAssetVersion(ctx, assetVersion)

			return next(ctx)
		}
	}
}

func EventMiddleware(repository shared.VulnEventRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	{
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx echo.Context) error {
				assetID := shared.GetAsset(ctx).ID

				eventID := ctx.Param("eventID")
				if eventID == "" {
					return echo.NewHTTPError(400, "eventID is required")
				}

				hasAccess, err := repository.HasAccessToEvent(ctx.Request().Context(), nil, assetID, eventID)
				if err != nil {
					return echo.NewHTTPError(500, "could not verify access to event").WithInternal(err)
				}
				if !hasAccess {
					return echo.NewHTTPError(403, "you do not have access to this event")
				}

				shared.SetEventID(ctx, eventID)
				return next(ctx)
			}
		}
	}
}
