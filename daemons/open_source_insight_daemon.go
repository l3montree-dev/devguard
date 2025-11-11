package daemon

import (
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
)

func UpdateOpenSourceInsightInformation(db shared.DB) error {
	strat := time.Now()
	defer func() {
		monitoring.UpdateOpenSourceInsightInformationDuration.Observe(time.Since(strat).Minutes())
	}()
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	projectsToUpdate, err := componentProjectRepository.FindAllOutdatedProjects()
	openSourceInsightsService := vulndb.NewOpenSourceInsightService()
	licenseRiskService := vuln.NewLicenseRiskService(repositories.NewLicenseRiskRepository(db), repositories.NewVulnEventRepository(db))
	componentService := component.NewComponentService(&openSourceInsightsService, componentProjectRepository, repositories.NewComponentRepository(db), licenseRiskService, repositories.NewArtifactRepository(db), utils.NewFireAndForgetSynchronizer())

	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, project := range projectsToUpdate {
		wg.Go(func() { componentService.RefreshComponentProjectInformation(project) })
	}

	wg.Wait()

	monitoring.UpdateOpenSourceInsightInformationDaemonAmount.Inc()
	return nil
}
