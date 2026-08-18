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
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// traceErr records err on span and turns it into an HTTP error with statusCode and msg.
func traceErr(span oteltrace.Span, statusCode int, msg string, err error) error {
	utils.RecordSpanError(span, err)
	return echo.NewHTTPError(statusCode, fmt.Sprintf("%s: %s", msg, err.Error())).WithInternal(err)
}

// sessionAvailableAssetIDs resolves the asset IDs the current session's RBAC grants access to.
func sessionAvailableAssetIDs(ctx shared.Context) ([]string, error) {
	rbac := shared.GetRBAC(ctx)
	return rbac.GetAllAssetsForSession(ctx.Request().Context(), shared.GetSession(ctx))
}

// sessionAssetIDsExcluding resolves the session's accessible asset IDs as
// uuid.UUID, leaving out excludeAssetID.
func sessionAssetIDsExcluding(ctx shared.Context, excludeAssetID uuid.UUID) ([]uuid.UUID, error) {
	ids, err := sessionAvailableAssetIDs(ctx)
	if err != nil {
		return nil, err
	}

	assetIDs := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == excludeAssetID {
			continue
		}
		assetIDs = append(assetIDs, parsed)
	}
	return assetIDs, nil
}

func ctxToBOMMetadata(ctx shared.Context) normalize.BOMMetadata {
	frontendURL := os.Getenv("FRONTEND_URL")

	assetVersion := shared.GetAssetVersion(ctx)
	artifactName := ""
	artifact, err := shared.MaybeGetArtifact(ctx)
	if err != nil {
		org := shared.GetOrg(ctx)
		project := shared.GetProject(ctx)

		asset := shared.GetAsset(ctx)
		artifactName = "pkg:devguard/" + org.Slug + "/" + project.Slug + "/" + asset.Slug
	} else {
		artifactName = artifact.ArtifactName
	}

	asset := shared.GetAsset(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)

	return normalize.BOMMetadata{
		AssetVersionSlug:      assetVersion.Slug,
		AssetSlug:             asset.Slug,
		OrgSlug:               org.Slug,
		ProjectSlug:           project.Slug,
		FrontendURL:           frontendURL,
		ArtifactName:          artifactName,
		AssetID:               asset.ID,
		AddExternalReferences: asset.SharesInformation,
		AssetVersionName:      assetVersion.Name,
	}
}
