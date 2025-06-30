package daemon

import (
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func ScanAssetVersions(db core.DB, rbacProvider core.RBACProvider) error {
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
	assetRiskHistoryRepository := repositories.NewAssetRiskHistoryRepository(db)
	projectRiskHistoryRepository := repositories.NewProjectRiskHistoryRepository(db)

	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)

	gitlabIntegration := gitlabint.NewGitlabIntegration(db, gitlabOauth2Integrations, rbacProvider, gitlabClientFactory)

	githubIntegration := githubint.NewGithubIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnerabilityRepository, vulnEventRepository, assetRepository)
	depsDevService := vulndb.NewDepsDevService()
	componentService := component.NewComponentService(&depsDevService, componentProjectRepository, componentRepository)

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnerabilityRepository, dependencyVulnService, firstPartyVulnService, assetRepository, vulnEventRepository, &componentService)

	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskHistoryRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, projectRiskHistoryRepository)

	s := scan.NewHTTPController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)

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

				monitoring.AssetVersionScanAmount.Inc()

				for i := range assetVersions {
					components, err := componentRepository.LoadComponents(db, assetVersions[i].Name, assetVersions[i].AssetID, "")
					if err != nil {
						slog.Error("failed to load components", "error", err)
						continue
					}

					// group the components by scannerID
					scannerIDMap := make(map[string][]models.ComponentDependency)
					for _, component := range components {
						scanner := strings.Fields(component.ScannerIDs)
						for _, scannerID := range scanner {
							scannerIDMap[scannerID] = append(scannerIDMap[scannerID], component)
						}
					}

					for scannerID, components := range scannerIDMap {
						bom := assetVersionService.BuildSBOM(assetVersions[i], "0.0.0", "", components)
						normalizedBOM := normalize.FromCdxBom(bom, false)
						if len(components) <= 0 {
							continue
						} else {
							_, err = s.ScanNormalizedSBOM(org, project, asset, assetVersions[i], normalizedBOM, scannerID, "system")
						}

						if err != nil {
							slog.Error("failed to scan normalized sbom", "error", err, "scannerID", scannerID, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
							continue
						}
					}

					monitoring.AssetVersionScanSuccess.Inc()
					slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
				}
			}
		}
	}
	monitoring.ScanDaemonAmount.Inc()
	return nil
}
