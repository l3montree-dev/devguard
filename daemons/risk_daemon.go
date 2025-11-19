package daemons

import (
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
)

func RecalculateRisk(
	dependencyVulnService shared.DependencyVulnService,
) error {
	start := time.Now()
	defer func() {
		monitoring.RecalculateAllRawRiskAssessmentsDuration.Observe(time.Since(start).Minutes())
	}()

	err := dependencyVulnService.RecalculateAllRawRiskAssessments()
	if err != nil {
		return err
	}
	monitoring.RecalculateRiskDaemonAmount.Inc()
	return nil
}
