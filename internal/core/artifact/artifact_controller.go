// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type controller struct {
	artifactService core.ArtifactService
}

func NewController(artifactService core.ArtifactService) *controller {
	return &controller{
		artifactService: artifactService,
	}
}

func (c *controller) DeleteArtifact(ctx core.Context) error {

	asset := core.GetAsset(ctx)

	assetVersion := core.GetAssetVersion(ctx)

	artifact := core.GetArtifact(ctx)

	err := c.artifactService.DeleteArtifact(asset.ID, assetVersion.Name, artifact.ArtifactName)

	if err != nil {
		return err
	}

	return ctx.NoContent(200)
}
