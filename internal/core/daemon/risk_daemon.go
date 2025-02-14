package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core/DependencyVuln"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func RecalculateRisk(db database.DB) error {
	dependencyVulnService := DependencyVuln.NewService(
		repositories.NewDependencyVulnerability(db),
		repositories.NewDependencyVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
	)

	return dependencyVulnService.RecalculateAllRawRiskAssessments()
}
