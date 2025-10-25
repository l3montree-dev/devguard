// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type controller struct {
	artifactRepository    core.ArtifactRepository
	artifactService       core.ArtifactService
	dependencyVulnService core.DependencyVulnService
	statisticsService     core.StatisticsService
	// mark public to let it be overridden in tests
	core.FireAndForgetSynchronizer
}

func NewController(artifactRepository core.ArtifactRepository, artifactService core.ArtifactService, dependencyVulnService core.DependencyVulnService, statisticsService core.StatisticsService) *controller {
	return &controller{
		artifactRepository:        artifactRepository,
		artifactService:           artifactService,
		dependencyVulnService:     dependencyVulnService,
		statisticsService:         statisticsService,
		FireAndForgetSynchronizer: utils.NewFireAndForgetSynchronizer(),
	}
}

func (c *controller) Create(ctx core.Context) error {

	asset := core.GetAsset(ctx)

	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)

	project := core.GetProject(ctx)

	type requestBody struct {
		ArtifactName string                       `json:"artifactName"`
		UpstreamURL  []models.ArtifactUpstreamURL `json:"upstreamUrls"`
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
	boms, _, _ := c.artifactService.FetchBomsFromUpstream(toAddURLs)
	if len(body.UpstreamURL) > 0 {
		err := c.artifactService.AddUpstreamURLs(&artifact, toAddURLs)
		if err != nil {
			return err
		}
	}
	vulns, err := c.artifactService.SyncUpstreamBoms(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
	if err != nil {
		slog.Error("could not sync vex reports", "err", err)
	}
	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)

		}

		// save the asset
		if err := c.artifactService.SaveArtifact(&artifact); err != nil {
			slog.Error("could not save artifact", "err", err)
		}
	})

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

	org := core.GetOrg(ctx)

	project := core.GetProject(ctx)

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
		UpstreamURL  []models.ArtifactUpstreamURL `json:"upstreamUrls"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	oldUpstreamURLs := artifact.UpstreamURLs
	newUpstreamURLs := body.UpstreamURL

	toDeleteURLs := []string{}
	toAddURLs := []string{}

	// Remove URLs that are not in the new list
	for _, oldURL := range oldUpstreamURLs {
		found := false
		for _, newURL := range newUpstreamURLs {
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
	for _, newURL := range newUpstreamURLs {
		found := false
		for _, oldURL := range oldUpstreamURLs {
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
	boms, validURLs, invalidURLs := c.artifactService.FetchBomsFromUpstream(toAddURLs)
	if len(toAddURLs) > 0 {
		err := c.artifactService.AddUpstreamURLs(&artifact, validURLs)
		if err != nil {
			return err
		}
	}

	vulns, err := c.artifactService.SyncUpstreamBoms(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
	if err != nil {
		slog.Error("could not sync vex reports", "err", err)
	}

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, vulns)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)

		}

		// save the asset
		if err := c.artifactService.SaveArtifact(&artifact); err != nil {
			slog.Error("could not save artifact", "err", err)
		}
	})

	artifact.UpstreamURLs = body.UpstreamURL

	type responseBody struct {
		Artifact    models.Artifact `json:"artifact"`
		InvalidURLs []string        `json:"invalidURLs"`
	}
	response := responseBody{
		Artifact:    artifact,
		InvalidURLs: invalidURLs,
	}
	return ctx.JSON(200, response)

}
