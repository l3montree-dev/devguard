// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
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

func (c *controller) UpdateArtifact(ctx core.Context) error {

	asset := core.GetAsset(ctx)

	assetVersion := core.GetAssetVersion(ctx)

	artifactName, err := core.GetArtifactName(ctx)
	if err != nil {
		return err
	}

	artifact, err := c.artifactService.ReadArtifact(artifactName, assetVersion.Name, asset.ID)
	if err != nil {
		return err
	}

	type requestBody struct {
		ArtifactName string                       `json:"artifactName"`
		UpstreamURL  []models.ArtifactUpstreamURL `json:"upstreamURLs"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	updateArtifact := false
	//sync changes
	if body.ArtifactName != "" && body.ArtifactName != artifact.ArtifactName {
		artifact.ArtifactName = body.ArtifactName
		updateArtifact = true
	}

	oldUpdateURLs := artifact.UpstreamURLs
	newUpdateURLs := body.UpstreamURL

	toDeleteURLs := []string{}
	toAddURLs := []string{}

	// Remove URLs that are not in the new list
	for _, oldURL := range oldUpdateURLs {
		found := false
		for _, newURL := range newUpdateURLs {
			if newURL.UpstreamURL == oldURL.UpstreamURL {
				found = true
				break
			}
		}
		if !found {
			toDeleteURLs = append(toDeleteURLs, oldURL.UpstreamURL)
		}
	}
	// Add URLs that are in the new list but not in the old list
	for _, newURL := range newUpdateURLs {
		found := false
		for _, oldURL := range oldUpdateURLs {
			if oldURL.UpstreamURL == newURL.UpstreamURL {
				found = true
				break
			}
		}
		if !found {
			toAddURLs = append(toAddURLs, newURL.UpstreamURL)
		}
	}

	if len(toDeleteURLs) > 0 {
		err := c.artifactService.RemoveUpstreamURLs(&artifact, toDeleteURLs)
		if err != nil {
			return err
		}
	}

	if len(toAddURLs) > 0 {
		err := c.artifactService.AddUpstreamURLs(&artifact, toAddURLs)
		if err != nil {
			return err
		}
	}

	artifact.UpstreamURLs = body.UpstreamURL
	if updateArtifact {
		err = c.artifactService.SaveArtifact(&artifact)
		if err != nil {
			return err
		}
	}

	return ctx.JSON(200, artifact)

}
