package daemons

import (
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
)

func UpdateOpenSourceInsightInformation(
	componentProjectRepository shared.ComponentProjectRepository,
	componentService shared.ComponentService,
) error {
	start := time.Now()
	defer func() {
		monitoring.UpdateOpenSourceInsightInformationDuration.Observe(time.Since(start).Minutes())
	}()

	projectsToUpdate, err := componentProjectRepository.FindAllOutdatedProjects()
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
