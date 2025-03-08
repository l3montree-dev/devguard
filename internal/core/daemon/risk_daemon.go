package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func RecalculateRisk(db core.DB) error {
	dependencyVulnService := dependencyVuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
	)

	return dependencyVulnService.RecalculateAllRawRiskAssessments()
}
