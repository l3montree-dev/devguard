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
	"os"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
)

func ctxToBOMMetadata(ctx shared.Context) normalize.BOMMetadata {
	orgSlug, _ := shared.GetOrgSlug(ctx)
	projectSlug, _ := shared.GetProjectSlug(ctx)
	frontendURL := os.Getenv("FRONTEND_URL")
	assetSlug, _ := shared.GetAssetSlug(ctx)

	assetVersion := shared.GetAssetVersion(ctx)
	artifact := shared.GetArtifact(ctx)
	asset := shared.GetAsset(ctx)

	return normalize.BOMMetadata{
		AssetVersionSlug:      assetVersion.Slug,
		AssetSlug:             assetSlug,
		OrgSlug:               orgSlug,
		ProjectSlug:           projectSlug,
		FrontendURL:           frontendURL,
		ArtifactName:          artifact.ArtifactName,
		AssetID:               asset.ID,
		AddExternalReferences: asset.SharesInformation,
		AssetVersionName:      assetVersion.Name,
	}
}
