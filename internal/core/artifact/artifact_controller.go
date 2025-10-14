// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type controller struct {
	artifactRepository core.ArtifactRepository
	artifactService    core.ArtifactService
}

func NewController(artifactRepository core.ArtifactRepository, artifactService core.ArtifactService) *controller {
	return &controller{
		artifactRepository: artifactRepository,
		artifactService:    artifactService,
	}
}

func (c *controller) Create(ctx core.Context) error {

	asset := core.GetAsset(ctx)

	assetVersion := core.GetAssetVersion(ctx)

	type requestBody struct {
		ArtifactName string                       `json:"artifactName"`
		UpstreamURL  []models.ArtifactUpstreamURL `json:"upstreamURLs"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	artifact := models.Artifact{
		ArtifactName:     body.ArtifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}

	//save the artifact
	err := c.artifactRepository.Create(nil, &artifact)
	if err != nil {
		return err
	}

	toAddURLs := []string{}
	for _, url := range body.UpstreamURL {
		toAddURLs = append(toAddURLs, url.UpstreamURL)
	}
	//check if the upstream urls are valid urls
	boms, _, _ := c.artifactService.CheckVexURLs(toAddURLs)
	if len(body.UpstreamURL) > 0 {

		err := c.artifactService.AddUpstreamURLs(&artifact, toAddURLs)
		if err != nil {
			return err
		}
	}
	err = c.artifactService.SyncVexReports(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
	if err != nil {
		return err
	}

	artifact.UpstreamURLs = body.UpstreamURL

	return ctx.JSON(201, artifact)

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

	//check if the upstream urls are valid urls
	//TODO: send the invalid urls back to the user
	boms, _, _ := c.artifactService.CheckVexURLs(toAddURLs)
	if len(toAddURLs) > 0 {
		err := c.artifactService.AddUpstreamURLs(&artifact, toAddURLs)
		if err != nil {
			return err
		}
	}

	err = c.artifactService.SyncVexReports(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
	if err != nil {
		return err
	}

	artifact.UpstreamURLs = body.UpstreamURL

	return ctx.JSON(200, artifact)

}

func (c *controller) SyncVexReports(boms []cdx.BOM, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, userID string) error {
	err := c.artifactService.SyncVexReports(boms, org, project, asset, assetVersion, artifact, userID)
	if err != nil {
		return err
	}
	return nil
}
