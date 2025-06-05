package inithelper

import (
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func CreateGithubIntegration(db core.DB) *githubint.GithubIntegration {
	return githubint.NewGithubIntegration(db)
}

func CreateGitlabIntegration(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory) *gitlabint.GitlabIntegration {
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)
	if err != nil {
		panic(err)
	}
	gitlabOauth2Integration := gitlabint.NewGitLabOauth2Integrations(db)
	return gitlabint.NewGitlabIntegration(db, gitlabOauth2Integration, casbinRBACProvider, clientFactory)
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

func CreateDepsDevService(db core.DB) core.DepsDevService {
	depsDevService := vulndb.NewDepsDevService()
	return &depsDevService
}

func CreateComponentService(db core.DB) core.ComponentService {
	componentService := component.NewComponentService(
		CreateDepsDevService(db),
		repositories.NewComponentProjectRepository(db),
		repositories.NewComponentRepository(db),
	)
	return &componentService
}

func CreateFirstPartyVulnService(db core.DB) core.FirstPartyVulnService {
	return vuln.NewFirstPartyVulnService(
		repositories.NewFirstPartyVulnerabilityRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
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
		integrations.NewThirdPartyIntegrations(CreateGitlabIntegration(db, oauth2, rbac, clientFactory), githubint.NewGithubIntegration(db)),
		repositories.NewAssetVersionRepository(db),
	)
}

func CreateAssetVersionService(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory) core.AssetVersionService {
	return assetversion.NewService(
		repositories.NewAssetVersionRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewFirstPartyVulnerabilityRepository(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		CreateFirstPartyVulnService(db),
		repositories.NewAssetRepository(db),
		repositories.NewVulnEventRepository(db),
		CreateComponentService(db),
	)
}

func CreateAssetVersionController(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory) *assetversion.AssetVersionController {
	return assetversion.NewAssetVersionController(
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, oauth2, rbac, clientFactory),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewComponentRepository(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
		repositories.NewSupplyChainRepository(db),
		repositories.NewLicenseOverwriteRepository(db),
	)
}

func CreateHttpController(db core.DB, oauth2 map[string]*gitlabint.GitlabOauth2Config, rbac core.RBACProvider, clientFactory core.GitlabClientFactory) *scan.HttpController {
	return scan.NewHttpController(
		db,
		repositories.NewCVERepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db, oauth2, rbac, clientFactory),
		CreateStatisticsService(db),
		CreateDependencyVulnService(db, oauth2, rbac, clientFactory),
	)
}
