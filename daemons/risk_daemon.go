package daemon

import (
	"time"

	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
)

func RecalculateRisk(db shared.DB, thirdPartyIntegrationAggregate shared.ThirdPartyIntegration) error {
	start := time.Now()
	defer func() {
		monitoring.RecalculateAllRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
	}()

	dependencyVulnService := services.NewDependencyVulnService(
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
