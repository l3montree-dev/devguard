package daemon

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func RecalculateRisk(db core.DB) error {
	start := time.Now()
	defer func() {
		monitoring.RecalculateAllRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
	}()

	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)
	if err != nil {
		panic(err)
	}

	githubIntegration := githubint.NewGithubIntegration(db)

	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)
	gitlabIntegration := gitlabint.NewGitLabIntegration(gitlabOauth2Integrations, db, casbinRBACProvider)

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

	err = dependencyVulnService.RecalculateAllRawRiskAssessments()
	if err != nil {
		return err
	}
	monitoring.RecalculateRiskDaemonAmount.Inc()
	return nil
}
