package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func RecalculateRisk(db database.DB) error {
	dependencyVulnService := dependencyVuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
	)

	gitlabIntegration := integrations.NewGitLabIntegration(db)
	githubIntegration := integrations.NewGithubIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabIntegration, githubIntegration)

	return dependencyVulnService.RecalculateAllRawRiskAssessments(thirdPartyIntegration)
}
