// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package controllers

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ArtifactController struct {
	artifactRepository       shared.ArtifactRepository
	artifactService          shared.ArtifactService
	dependencyVulnService    shared.DependencyVulnService
	dependencyVulnRepository shared.DependencyVulnRepository
	statisticsService        shared.StatisticsService
	componentService         shared.ComponentService
	assetVersionService      shared.AssetVersionService
	vexRuleService           shared.VEXRuleService
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
	shared.ScanService
}

func NewArtifactController(artifactRepository shared.ArtifactRepository, artifactService shared.ArtifactService, assetVersionService shared.AssetVersionService, dependencyVulnService shared.DependencyVulnService, statisticsService shared.StatisticsService, componentService shared.ComponentService, scanService shared.ScanService, synchronizer utils.FireAndForgetSynchronizer, dependencyVulnRepository shared.DependencyVulnRepository) *ArtifactController {
	return &ArtifactController{
		artifactRepository:        artifactRepository,
		artifactService:           artifactService,
		dependencyVulnService:     dependencyVulnService,
		statisticsService:         statisticsService,
		FireAndForgetSynchronizer: synchronizer,
		componentService:          componentService,
		assetVersionService:       assetVersionService,
		dependencyVulnRepository:  dependencyVulnRepository,
		ScanService:               scanService,
	}
}

type informationSource struct {
	URL  string  `json:"url"`
	Purl *string `json:"purl"`
	// type can be "csaf", "vex", "sbom"
	Type string `json:"type,omitempty"`
}

func informationSourceToString(source informationSource) string {
	r := source.URL
	if source.Purl != nil && *source.Purl != "" {
		r = *source.Purl + ":" + r
	}
	if source.Type != "" {
		r = source.Type + ":" + r
	}
	return r
}

// @Summary Create artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param body body object true "Artifact data"
// @Success 201 {object} models.Artifact
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts [post]
func (c *ArtifactController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)

	project := shared.GetProject(ctx)

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
	boms, vexReports, _, _ := c.FetchBomsFromUpstream(artifact.ArtifactName, artifact.AssetVersionName, utils.Map(body.InformationSources, informationSourceToString))
	tx := c.artifactRepository.GetDB(nil).Begin()

	// merge all boms
	newGraph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		newGraph.MergeGraph(bom) // we dont care for the diff
	}

	bom, err := c.assetVersionService.UpdateSBOM(tx, org, project, asset, assetVersion, artifact.ArtifactName, newGraph, asset.DesiredUpstreamStateForEvents())

	if err != nil {
		tx.Rollback()
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}
	currentUserID := shared.GetSession(ctx).GetUserID()

	_, _, newState, err := c.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, bom, currentUserID)

	if err != nil {
		tx.Rollback()
		slog.Error("could not scan sbom after creating artifact", "err", err)
		return echo.NewHTTPError(500, "could not scan sbom after creating artifact").WithInternal(err)
	}

	if err := c.vexRuleService.IngestVexes(tx, asset, vexReports); err != nil {
		tx.Rollback()
		slog.Error("could not ingest vex reports", "err", err)
		return err
	}

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, newState)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	return ctx.JSON(201, artifact)
}

// @Summary Delete artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName} [delete]
func (c *ArtifactController) DeleteArtifact(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)

	assetVersion := shared.GetAssetVersion(ctx)

	artifact := shared.GetArtifact(ctx)

	// Extract org and project before FireAndForget since Echo contexts are not goroutine-safe
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)

	// we need to sync the vulnerabilities after deleting the artifact
	// maybe we need to close some: https://github.com/l3montree-dev/devguard/issues/1496
	// fetch all vulnerabilities which ONLY belong to this artifact
	vulns, err := c.dependencyVulnRepository.GetAllVulnsByArtifact(nil, artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch vulnerabilities").WithInternal(err)
	}
	syncVulns := make([]models.DependencyVuln, 0)
	// check which vulns will be removed completely
	for _, vuln := range vulns {
		if len(vuln.Artifacts) <= 1 {
			// mark it as fixed so it gets closed in the issue tracker
			vuln.State = dtos.VulnStateFixed
			syncVulns = append(syncVulns, vuln)
		}
	}

	if len(syncVulns) > 0 {
		c.FireAndForget(func() {
			err := c.dependencyVulnService.SyncIssues(org, project, asset, assetVersion, syncVulns)
			if err != nil {
				slog.Error("could not sync issues for vulnerabilities after artifact deletion", "err", err)
			}
		})
	}

	// DeleteArtifact now handles depth recalculation internally
	err = c.artifactService.DeleteArtifact(asset.ID, assetVersion.Name, artifact.ArtifactName)

	if err != nil {
		return err
	}

	return ctx.NoContent(200)
}

// @Summary Sync external sources for artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/sync [post]
func (c *ArtifactController) SyncExternalSources(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := shared.GetArtifact(ctx)
	org := shared.GetOrg(ctx)
	sources, err := c.componentService.FetchInformationSources(&artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch artifact root nodes").WithInternal(err)
	}

	boms, vexReports, _, _ := c.FetchBomsFromUpstream(artifact.ArtifactName, artifact.AssetVersionName, utils.UniqBy(utils.Map(sources, func(el models.ComponentDependency) string {
		_, origin := normalize.RemoveInformationSourcePrefixIfExists(el.DependencyID)
		return origin
	}), func(el string) string {
		return el
	}))
	var vulns []models.DependencyVuln

	tx := c.artifactRepository.Begin()

	graph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		graph.MergeGraph(bom)
	}

	sbom, err := c.assetVersionService.UpdateSBOM(tx, org, shared.GetProject(ctx), asset, assetVersion, artifact.ArtifactName, graph, asset.DesiredUpstreamStateForEvents())
	if err != nil {
		tx.Rollback()
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}

	_, _, vulns, err = c.ScanNormalizedSBOM(tx, org, shared.GetProject(ctx), asset, assetVersion, artifact, sbom, shared.GetSession(ctx).GetUserID())

	if err != nil {
		tx.Rollback()
		slog.Error("could not scan sbom after syncing external sources", "err", err)
		return echo.NewHTTPError(500, "could not scan sbom after syncing external sources").WithInternal(err)
	}

	if err := c.vexRuleService.IngestVexes(tx, asset, vexReports); err != nil {
		tx.Rollback()
		slog.Error("could not ingest vex reports", "err", err)
		return err
	}

	tx.Commit()

	c.FireAndForget(func() {
		err := c.dependencyVulnService.SyncIssues(org, shared.GetProject(ctx), asset, assetVersion, vulns)
		if err != nil {
			slog.Error("could not create issues for vulnerabilities", "err", err)
		}
	})

	c.FireAndForget(func() {
		slog.Info("recalculating risk history for asset", "asset version", assetVersion.Name, "assetID", asset.ID)
		if err := c.statisticsService.UpdateArtifactRiskAggregation(&artifact, asset.ID, utils.OrDefault(artifact.LastHistoryUpdate, assetVersion.CreatedAt), time.Now()); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
		}
	})

	return nil
}

// @Summary Update artifact
// @Tags Artifacts
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Param body body object true "Artifact data"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName} [put]
func (c *ArtifactController) UpdateArtifact(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	artifactName, err := shared.GetArtifactName(ctx)
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
		return el.DependencyID
	}), func(e string) string { return e })

	toAdd := comparison.OnlyInA
	toDelete := comparison.OnlyInB

	// we just need to remove those root nodes.
	if err := c.componentService.RemoveInformationSources(&artifact, toDelete); err != nil {
		return echo.NewHTTPError(500, "could not remove root nodes").WithInternal(err)
	}

	//check if the upstream urls are valid urls
	boms, vexReports, _, invalidURLs := c.FetchBomsFromUpstream(artifactName, artifact.AssetVersionName, toAdd)
	var vulns []models.DependencyVuln

	graph := normalize.NewSBOMGraph()
	for _, bom := range boms {
		graph.MergeGraph(bom)
	}

	tx := c.artifactRepository.Begin()

	// make sure that we at least update the sbom once if there were deletions
	// updating with nil, will just renormalize the sbom and remove all components which are not
	// reachable anymore from the root nodes - we might have removed some root nodes above
	sbom, err := c.assetVersionService.UpdateSBOM(tx, org, project, asset, assetVersion, artifact.ArtifactName, graph, asset.DesiredUpstreamStateForEvents())
	if err != nil {
		slog.Error("could not update sbom", "err", err)
		return echo.NewHTTPError(500, "could not update sbom").WithInternal(err)
	}

	_, _, vulns, err = c.ScanNormalizedSBOM(tx, org, project, asset, assetVersion, artifact, sbom, shared.GetSession(ctx).GetUserID())
	if err != nil {
		slog.Error("could not scan sbom after updating it", "err", err)
		return echo.NewHTTPError(500, "could not scan sbom after updating it").WithInternal(err)
	}

	if err := c.vexRuleService.IngestVexes(tx, asset, vexReports); err != nil {
		tx.Rollback()
		slog.Error("could not ingest vex reports", "err", err)
		return err
	}

	tx.Commit()

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
