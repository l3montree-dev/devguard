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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
)

func ctxToBOMMetadata(ctx shared.Context, asset models.Asset) normalize.BOMMetadata {
	assetVersionSlug, _ := shared.GetAssetVersionSlug(ctx)
	orgSlug, _ := shared.GetOrgSlug(ctx)
	projectSlug, _ := shared.GetProjectSlug(ctx)
	frontendURL := os.Getenv("FRONTEND_URL")
	assetSlug, _ := shared.GetAssetSlug(ctx)

	// Try to get artifact name from URL param first, then from context
	artifactName, err := shared.GetArtifactName(ctx)
	if err != nil || artifactName == "" {
		// Fall back to artifact in context
		artifact, err := shared.MaybeGetArtifact(ctx)
		if err == nil {
			artifactName = artifact.ArtifactName
		}
	}

	var assetID *uuid.UUID
	addExternalReferences := false
	if asset.SharesInformation {
		assetID = &asset.ID
		addExternalReferences = true
	}

	return normalize.BOMMetadata{
		AssetVersionSlug:      assetVersionSlug,
		AssetSlug:             assetSlug,
		OrgSlug:               orgSlug,
		ProjectSlug:           projectSlug,
		FrontendURL:           frontendURL,
		ArtifactName:          artifactName,
		AssetID:               assetID,
		AddExternalReferences: addExternalReferences,
	}
}
