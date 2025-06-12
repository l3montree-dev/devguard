package daemon

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func RecalculateRisk(db core.DB, thirdPartyIntegrationAggregate core.ThirdPartyIntegration) error {
	start := time.Now()
	defer func() {
		monitoring.RecalculateAllRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
	}()

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
