// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jiraint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/webhook"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func SyncReports(db core.DB, rbacProvider core.RBACProvider) error {

	start := time.Now()
	defer func() {
		monitoring.ScanDaemonDuration.Observe(time.Since(start).Minutes())
	}()

	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnerabilityRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	componentProjectRepository := repositories.NewComponentProjectRepository(db)

	licenseRiskRepository := repositories.NewLicenseRiskRepository(db)

	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)
	webhookIntegration := webhook.NewWebhookIntegration(db)
	artifactRepository := repositories.NewArtifactRepository(db)
	jiraIntegration := jiraint.NewJiraIntegration(db)
	gitlabIntegration := gitlabint.NewGitlabIntegration(db, gitlabOauth2Integrations, rbacProvider, gitlabClientFactory)

	githubIntegration := githubint.NewGithubIntegration(db)
	externalUserRepository := repositories.NewExternalUserRepository(db)

	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(externalUserRepository, githubIntegration, gitlabIntegration, jiraIntegration, webhookIntegration)

	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnerabilityRepository, vulnEventRepository, assetRepository, thirdPartyIntegration)
	openSourceInsightsService := vulndb.NewOpenSourceInsightService()
	licenseRiskService := vuln.NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)
	componentService := component.NewComponentService(&openSourceInsightsService, componentProjectRepository, componentRepository, licenseRiskService, artifactRepository, utils.NewFireAndForgetSynchronizer())

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnerabilityRepository, dependencyVulnService, firstPartyVulnService, assetRepository, projectRepository, orgRepository, vulnEventRepository, &componentService, thirdPartyIntegration, licenseRiskRepository)

	artifactService := artifact.NewService(artifactRepository, cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)

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
				assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDBByAssetID(db, asset.ID)
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
						// Convert []models.ArtifactUpstreamURL to []string
						upstreamURLs := make([]string, len(artifact.UpstreamURLs))
						for i, u := range artifact.UpstreamURLs {
							upstreamURLs[i] = u.UpstreamURL
						}
						vexReports, _, _ := artifactService.CheckVexURLs(upstreamURLs)

						err := artifactService.SyncReports(vexReports, org, project, asset, assetVersions[i], artifact, "system")
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
