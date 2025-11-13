package daemons

import (
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
)

func UpdateOpenSourceInsightInformation(db shared.DB) error {
	strat := time.Now()
	defer func() {
		monitoring.UpdateOpenSourceInsightInformationDuration.Observe(time.Since(strat).Minutes())
	}()
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	projectsToUpdate, err := componentProjectRepository.FindAllOutdatedProjects()
	openSourceInsightsService := vulndb.NewOpenSourceInsightService()
	licenseRiskService := services.NewLicenseRiskService(repositories.NewLicenseRiskRepository(db), repositories.NewVulnEventRepository(db))
	componentService := services.NewComponentService(&openSourceInsightsService, componentProjectRepository, repositories.NewComponentRepository(db), licenseRiskService, repositories.NewArtifactRepository(db), utils.NewFireAndForgetSynchronizer())

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
