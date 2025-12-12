// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemons

import (
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func SyncUpstream(
	db shared.DB,
	assetVersionService shared.AssetVersionService,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
	artifactService shared.ArtifactService,
	componentService shared.ComponentService,
) error {

	start := time.Now()
	defer func() {
		monitoring.ScanDaemonDuration.Observe(time.Since(start).Minutes())
	}()

	orgs, err := orgRepository.All()
	if err != nil {
		return err
	}

	for _, org := range orgs {
		// get all projects for the org
		projects, err := projectRepository.GetByOrgID(org.ID)
		if err != nil {
			slog.Error("failed to load projects for org", "orgID", org.ID, "error", err)
			continue
		}
		for _, project := range projects {
			// get all assets for the project
			assets, err := assetRepository.GetByProjectID(project.ID)
			if err != nil {
				slog.Error("failed to load assets for project", "projectID", project.ID, "error", err)
				continue
			}
			for _, asset := range assets {
				// get all asset versions for the asset
				assetVersions, err := assetVersionRepository.GetAssetVersionsByAssetID(db, asset.ID)
				if err != nil {
					slog.Error("failed to load asset versions for asset", "assetID", asset.ID, "error", err)
					continue
				}
				for i := range assetVersions {
					artifacts, err := artifactService.GetArtifactNamesByAssetIDAndAssetVersionName(assetVersions[i].AssetID, assetVersions[i].Name)
					if err != nil {
						slog.Error("failed to get artifacts for asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
						continue
					}

					for _, artifact := range artifacts {
						rootNodes, err := componentService.FetchInformationSources(&artifact)
						if err != nil {
							slog.Error("failed to fetch root nodes for artifact", "artifact", artifact.ArtifactName, "assetVersion", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
							continue
						}

						upstreamURLs := utils.UniqBy(utils.Filter(utils.Map(rootNodes, func(el models.ComponentDependency) string {
							_, origin := normalize.RemoveOriginTypePrefixIfExists(el.DependencyPurl)
							return origin
						}), func(el string) bool {
							return strings.HasPrefix(el, "http")
						}), func(el string) string {
							return el
						})

						vexReports, _, _ := artifactService.FetchBomsFromUpstream(artifact.ArtifactName, artifact.AssetVersionName, upstreamURLs)

						_, err = artifactService.SyncUpstreamBoms(vexReports, org, project, asset, assetVersions[i], artifact, "system")
						if err != nil {
							slog.Error("failed to sync VEX reports", "artifact", artifact.ArtifactName, "assetVersion", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
							continue
						}

					}
				}
			}
		}

	}

	return nil
}
