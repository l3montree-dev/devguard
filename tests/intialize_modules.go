// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/githubint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

// DEPRECATED: These functions manually wire dependencies, which causes import cycles
// and maintenance burden. Use NewTestApp() from fx_test_app.go instead, which uses
// the same FX modules as production for consistency.
//
// Migration example:
//   OLD: svc := tests.CreateLicenseRiskService(db)
//   NEW: app, _ := tests.NewTestApp(db)
//        svc := app.LicenseRiskService

func CreateLicenseRiskService(db shared.DB) shared.LicenseRiskService {
	return services.NewLicenseRiskService(
		repositories.NewLicenseRiskRepository(db),
		repositories.NewVulnEventRepository(db),
	)
}

func CreateStatisticsService(db shared.DB) shared.StatisticsService {
	return services.NewStatisticsService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewArtifactRiskHistoryRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewAssetVersionRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewReleaseRepository(db),
	)
}

func CreateComponentService(db shared.DB, openSourceInsightsService shared.OpenSourceInsightService) shared.ComponentService {
	componentService := services.NewComponentService(
		openSourceInsightsService,
		repositories.NewComponentProjectRepository(db),
		repositories.NewComponentRepository(db),
		CreateLicenseRiskService(db),
		repositories.NewArtifactRepository(db),
		utils.NewSyncFireAndForgetSynchronizer(),
	)
	return &componentService
}

func CreateFirstPartyVulnService(db shared.DB, thirdPartyIntegration shared.IntegrationAggregate) shared.FirstPartyVulnService {
	return services.NewFirstPartyVulnService(
		repositories.NewFirstPartyVulnerabilityRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		thirdPartyIntegration,
	)
}

func CreateDependencyVulnService(db shared.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac shared.RBACProvider, clientFactory gitlabint.GitlabClientFactory) shared.DependencyVulnService {
	return services.NewDependencyVulnService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		integrations.NewThirdPartyIntegrations(repositories.NewExternalUserRepository(db), gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory), githubint.NewGithubIntegration(db)),
		repositories.NewAssetVersionRepository(db),
	)
}

func CreateArtifactService(db shared.DB, openSourceInsightsService shared.OpenSourceInsightService) shared.ArtifactService {
	return services.NewArtifactService(
		repositories.NewArtifactRepository(db),
		services.NewCSAFService(common.OutgoingConnectionClient),
		repositories.NewCVERepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, nil, nil, nil, openSourceInsightsService),
		CreateDependencyVulnService(db, nil, nil, nil),
	)
}

func CreateAssetVersionService(db shared.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac shared.RBACProvider, clientFactory gitlabint.GitlabClientFactory, openSourceInsightsService shared.OpenSourceInsightService) shared.AssetVersionService {
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(repositories.NewExternalUserRepository(db), gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory), githubint.NewGithubIntegration(db))
	s := services.NewAssetVersionService(
		repositories.NewAssetVersionRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewFirstPartyVulnerabilityRepository(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		CreateFirstPartyVulnService(db, thirdPartyIntegration),
		repositories.NewAssetRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewVulnEventRepository(db),
		CreateComponentService(db, openSourceInsightsService),
		thirdPartyIntegration,
		repositories.NewLicenseRiskRepository(db),
	)
	s.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()
	return s
}

func CreateAssetVersionController(db shared.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac shared.RBACProvider, clientFactory gitlabint.GitlabClientFactory, openSourceInsightsService shared.OpenSourceInsightService) *controllers.AssetVersionController {
	cmpService := services.NewComponentService(
		openSourceInsightsService,
		repositories.NewComponentProjectRepository(db),
		repositories.NewComponentRepository(db),
		CreateLicenseRiskService(db),
		repositories.NewArtifactRepository(db),
		utils.NewSyncFireAndForgetSynchronizer(),
	)
	return controllers.NewAssetVersionController(
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, oauth2, rbac, clientFactory, openSourceInsightsService),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewComponentRepository(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		repositories.NewSupplyChainRepository(db),
		repositories.NewLicenseRiskRepository(db),
		&cmpService,
		services.NewStatisticsService(
			repositories.NewStatisticsRepository(db),
			repositories.NewComponentRepository(db),
			repositories.NewArtifactRiskHistoryRepository(db),
			repositories.NewDependencyVulnRepository(db),
			repositories.NewAssetVersionRepository(db),
			repositories.NewProjectRepository(db),
			repositories.NewReleaseRepository(db),
		),
		CreateArtifactService(db, openSourceInsightsService),
	)
}

func CreateScanHTTPController(db shared.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac shared.RBACProvider, clientFactory gitlabint.GitlabClientFactory, openSourceInsightsService shared.OpenSourceInsightService) *controllers.ScanController {
	assetVersionService := CreateAssetVersionService(db, oauth2, rbac, clientFactory, openSourceInsightsService)
	dependencyVulnService := CreateDependencyVulnService(db, oauth2, rbac, clientFactory)
	artifactService := CreateArtifactService(db, openSourceInsightsService)
	dependencyVulnRepo := repositories.NewDependencyVulnRepository(db)
	statisticsService := CreateStatisticsService(db)
	scanService := services.NewScanService(db,
		repositories.NewCVERepository(db),
		assetVersionService,
		dependencyVulnService,
		artifactService,
		statisticsService,
	)
	scanService.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()
	return controllers.NewScanController(
		scanService,
		repositories.NewComponentRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewAssetVersionRepository(db),
		assetVersionService,
		statisticsService,
		dependencyVulnService,
		CreateFirstPartyVulnService(db, integrations.NewThirdPartyIntegrations(
			repositories.NewExternalUserRepository(db),
			gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory),
			githubint.NewGithubIntegration(db),
		)),
		artifactService,
		dependencyVulnRepo,
	)
}
