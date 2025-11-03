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
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func ScanArtifacts(db core.DB, rbacProvider core.RBACProvider) error {
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
	statisticsRepository := repositories.NewStatisticsRepository(db)
	assetRiskHistoryRepository := repositories.NewArtifactRiskHistoryRepository(db)
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
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskHistoryRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewReleaseRepository(db))
	scanService := scan.NewScanService(db, cveRepository, assetVersionService, dependencyVulnService, artifactService, statisticsService)

	s := scan.NewHTTPController(scanService, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService, firstPartyVulnService, artifactService, dependencyVulnRepository)
	// THIS IS MANDATORY - WE RESET THE SYNCHRONIZER.
	// if we wont do that, the daemon would sync the issues in a goroutine without waiting for them to finish
	// this might infer with the ticket daemon which runs next
	/*
		ScanArtifacts --> Create Ticket ----------------> Completed
		              Ticket Daemon starts ----> Create Ticket ----> Completed

		If the ticket daemon starts creating tickets before the scan artifacts daemon has finished creating tickets, there might be duplicate tickets created for the same vulnerability.

		Ref: https://github.com/l3montree-dev/devguard/issues/1284
		Ref: https://github.com/l3montree-dev/devguard/issues/1285
	*/

	s.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()

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

				monitoring.AssetVersionScanAmount.Inc()

				for i := range assetVersions {

					artifacts, err := artifactService.GetArtifactNamesByAssetIDAndAssetVersionName(assetVersions[i].AssetID, assetVersions[i].Name)
					if err != nil {
						slog.Error("failed to get artifacts for asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
						continue
					}

					for _, artifact := range artifacts {

						components, err := componentRepository.LoadComponents(db, assetVersions[i].Name, assetVersions[i].AssetID, &artifact.ArtifactName)
						if err != nil {
							slog.Error("failed to load components", "error", err)
							continue
						}

						bom, err := assetVersionService.BuildSBOM(asset, assetVersions[i], artifact.ArtifactName, "", components)
						if err != nil {
							slog.Error("error when building SBOM")
							continue
						}
						if len(components) <= 0 {
							continue
						} else {
							_, _, _, err = s.ScanNormalizedSBOM(org, project, asset, assetVersions[i], artifact, bom, "system")
						}

						if err != nil {
							slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
							continue
						}

						monitoring.AssetVersionScanSuccess.Inc()
						slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
					}
				}
			}
		}
	}
	monitoring.ScanDaemonAmount.Inc()
	return nil
}
