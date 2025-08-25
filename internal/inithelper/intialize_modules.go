package inithelper

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func CreateLicenseRiskService(db core.DB) core.LicenseRiskService {
	return vuln.NewLicenseRiskService(
		repositories.NewLicenseRiskRepository(db),
		repositories.NewVulnEventRepository(db),
	)
}

func CreateStatisticsService(db core.DB) core.StatisticsService {
	return statistics.NewService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRiskHistoryRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewAssetVersionRepository(db),
		repositories.NewProjectRepository(db),
		repositories.NewProjectRiskHistoryRepository(db),
	)
}

func CreateComponentService(db core.DB, depsDevService core.DepsDevService) core.ComponentService {
	componentService := component.NewComponentService(
		depsDevService,
		repositories.NewComponentProjectRepository(db),
		repositories.NewComponentRepository(db),
		CreateLicenseRiskService(db),
	)
	return &componentService
}

func CreateFirstPartyVulnService(db core.DB, thirdPartyIntegration core.ThirdPartyIntegration) core.FirstPartyVulnService {
	return vuln.NewFirstPartyVulnService(
		repositories.NewFirstPartyVulnerabilityRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		thirdPartyIntegration,
	)
}

func CreateDependencyVulnService(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory) core.DependencyVulnService {
	return vuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		integrations.NewThirdPartyIntegrations(gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory), githubint.NewGithubIntegration(db)),
		repositories.NewAssetVersionRepository(db),
	)
}

func CreateAssetVersionService(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory, depsDevService core.DepsDevService) core.AssetVersionService {
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory), githubint.NewGithubIntegration(db))
	return assetversion.NewService(
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
		CreateComponentService(db, depsDevService),
		thirdPartyIntegration,
		repositories.NewLicenseRiskRepository(db),
	)
}

func CreateAssetVersionController(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory, depsDevService core.DepsDevService) *assetversion.AssetVersionController {
	cmpService := component.NewComponentService(
		depsDevService,
		repositories.NewComponentProjectRepository(db),
		repositories.NewComponentRepository(db),
		CreateLicenseRiskService(db),
	)
	return assetversion.NewAssetVersionController(
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, oauth2, rbac, clientFactory, depsDevService),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewComponentRepository(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		repositories.NewSupplyChainRepository(db),
		repositories.NewLicenseRiskRepository(db),
		&cmpService,
	)
}

func CreateHTTPController(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory, depsDevService core.DepsDevService) *scan.HTTPController {
	return scan.NewHTTPController(
		db,
		repositories.NewCVERepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, oauth2, rbac, clientFactory, depsDevService),
		CreateStatisticsService(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		CreateFirstPartyVulnService(db, integrations.NewThirdPartyIntegrations(
			gitlabint.NewGitlabIntegration(db, oauth2, rbac, clientFactory),
			githubint.NewGithubIntegration(db),
		)),
	)
}
