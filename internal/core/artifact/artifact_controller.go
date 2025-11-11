// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package artifact

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type controller struct {
	artifactRepository    core.ArtifactRepository
	artifactService       core.ArtifactService
	dependencyVulnService core.DependencyVulnService
	statisticsService     core.StatisticsService
	componentService      core.ComponentService
	assetVersionService   core.AssetVersionService
	// mark public to let it be overridden in tests
	core.FireAndForgetSynchronizer
	core.ScanService
}

func NewController(artifactRepository core.ArtifactRepository, artifactService core.ArtifactService, assetVersionService core.AssetVersionService, dependencyVulnService core.DependencyVulnService, statisticsService core.StatisticsService, componentService core.ComponentService, scanService core.ScanService) *controller {
	return &controller{
		artifactRepository:        artifactRepository,
		artifactService:           artifactService,
		dependencyVulnService:     dependencyVulnService,
		statisticsService:         statisticsService,
		FireAndForgetSynchronizer: utils.NewFireAndForgetSynchronizer(),
		componentService:          componentService,
		assetVersionService:       assetVersionService,
		ScanService:               scanService,
	}
}

type informationSource struct {
	Purl string `json:"purl,omitempty"`
	// type can be "csaf", "vex", "sbom"
	Type string `json:"type,omitempty"`
}

func informationSourceToString(source informationSource) string {
	if source.Type == "" {
		return source.Purl
	}

	return source.Type + ":" + source.Purl
}

func (c *controller) Create(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)

	project := core.GetProject(ctx)

	type requestBody struct {
		ArtifactName       string              `json:"artifactName"`
		InformationSources []informationSource `json:"informationSources"`
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

	//check if the upstream urls are valid urls
	boms, _, _ := c.artifactService.FetchBomsFromUpstream(artifact.ArtifactName, utils.Map(body.InformationSources, informationSourceToString))
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

func (c *controller) SyncExternalSources(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	artifact := core.GetArtifact(ctx)
	org := core.GetOrg(ctx)
	sources, err := c.componentService.FetchInformationSources(&artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch artifact root nodes").WithInternal(err)
	}

	boms, _, _ := c.artifactService.FetchBomsFromUpstream(artifact.ArtifactName, utils.UniqBy(utils.Map(sources, func(el models.ComponentDependency) string {
		_, origin := normalize.RemoveOriginTypePrefixIfExists(el.DependencyPurl)
		return origin
	}), func(el string) string {
		return el
	}))
	var vulns []models.DependencyVuln

	if len(boms) > 0 {
		vulns, err = c.artifactService.SyncUpstreamBoms(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
		if err != nil {
			slog.Error("could not sync vex reports", "err", err)
		}
	}

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, core.GetProject(ctx), asset, assetVersion, vulns)
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

	return nil
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
		ArtifactName       string              `json:"artifactName"`
		InformationSources []informationSource `json:"informationSources"`
	}

	var body requestBody

	if err := ctx.Bind(&body); err != nil {
		return err
	}

	oldSources, err := c.componentService.FetchInformationSources(&artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch artifact root nodes").WithInternal(err)
	}

	comparison := utils.CompareSlices(utils.Map(body.InformationSources, informationSourceToString), utils.Map(oldSources, func(el models.ComponentDependency) string {
		return el.DependencyPurl
	}), func(e string) string { return e })

	toAdd := comparison.OnlyInA
	toDelete := comparison.OnlyInB

	// we just need to remove those root nodes.
	if err := c.componentService.RemoveInformationSources(&artifact, toDelete); err != nil {
		return echo.NewHTTPError(500, "could not remove root nodes").WithInternal(err)
	}

	//check if the upstream urls are valid urls
	boms, _, invalidURLs := c.artifactService.FetchBomsFromUpstream(artifactName, toAdd)
	var vulns []models.DependencyVuln
	if len(boms) > 0 {
		vulns, err = c.artifactService.SyncUpstreamBoms(boms, core.GetOrg(ctx), core.GetProject(ctx), asset, assetVersion, artifact, "system")
		if err != nil {
			slog.Error("could not sync vex reports", "err", err)
		}
	} else if len(toDelete) > 0 {
		// make sure that we at least update the sbom once if there were deletions
		// updating with nil, will just renormalize the sbom and remove all components which are not
		// reachable anymore from the root nodes - we might have removed some root nodes above
		sbom, err := c.assetVersionService.UpdateSBOM(org, project, asset, assetVersion, artifact.ArtifactName, nil, models.UpstreamStateExternal)
		if err != nil {
			slog.Error("could not update sbom", "err", err)
			return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
		}
		// scan the sbom
		// issue sync is already handled in scan normalized sbom
		_, _, vulns, err = c.ScanNormalizedSBOM(org, project, asset, assetVersion, artifact, sbom, core.GetSession(ctx).GetUserID())
		if err != nil {
			slog.Error("could not scan sbom after updating it", "err", err)
			return echo.NewHTTPError(500, "could not scan sbom after updating it").WithInternal(err)
		}
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
