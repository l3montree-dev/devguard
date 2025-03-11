package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func RecalculateRisk(db core.DB) error {
	dependencyVulnService := dependency_vuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
	)

	return dependencyVulnService.RecalculateAllRawRiskAssessments()
}
