package daemon

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func RecalculateRisk(db core.DB) error {
	start := time.Now()
	defer func() {
		monitoring.RecalculateAllRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
	}()
	githubIntegration := integrations.NewGithubIntegration(db)

	gitlabOauth2Integrations := integrations.NewGitLabOauth2Integrations(db)
	gitlabIntegration := integrations.NewGitLabIntegration(gitlabOauth2Integrations, db)

	thirdPartyIntegrationAggregate := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

	dependencyVulnService := vuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		thirdPartyIntegrationAggregate,
		repositories.NewAssetVersionRepository(db),
	)

	err := dependencyVulnService.RecalculateAllRawRiskAssessments()
	if err != nil {
		return err
	}
	monitoring.RecalculateRiskDaemonAmount.Inc()
	return nil
}
