package inithelper

import (
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func CreateGithubIntegration(db core.DB) *githubint.GithubIntegration {
	return githubint.NewGithubIntegration(db)
}

func CreateGitlabIntegration(db core.DB) *gitlabint.GitlabIntegration {
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)
	if err != nil {
		panic(err)
	}
	gitlabOauth2Integration := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integration,
	)

	return gitlabint.NewGitlabIntegration(db, gitlabOauth2Integration, casbinRBACProvider, gitlabClientFactory)
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

func CreateDependencyVulnService(db core.DB) core.DependencyVulnService {

	return vuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		integrations.NewThirdPartyIntegrations(CreateGitlabIntegration(db), CreateGithubIntegration(db)),
		repositories.NewAssetVersionRepository(db),
	)
}

func CreateAssetVersionService(db core.DB) core.AssetVersionService {
	return assetversion.NewService(
		repositories.NewAssetVersionRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewFirstPartyVulnerabilityRepository(db),
		CreateDependencyVulnService(db),
		CreateFirstPartyVulnService(db),
		repositories.NewAssetRepository(db),
		repositories.NewVulnEventRepository(db),
		CreateComponentService(db),
	)
}

func CreateAssetVersionController(db core.DB) *assetversion.AssetVersionController {
	return assetversion.NewAssetVersionController(
		repositories.NewAssetVersionRepository(db),
		CreateAssetVersionService(db),
		repositories.NewDependencyVulnRepository(db),
		repositories.NewComponentRepository(db),
		CreateDependencyVulnService(db),
		repositories.NewSupplyChainRepository(db),
		repositories.NewLicenseOverwriteRepository(db),
	)
}
