package daemons

import (
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
)

func (runner *DaemonRunner) UpdateOpenSourceInsightInformation() error {
	start := time.Now()
	defer func() {
		monitoring.UpdateOpenSourceInsightInformationDuration.Observe(time.Since(start).Minutes())
	}()

	projectsToUpdate, err := runner.componentProjectRepository.FindAllOutdatedProjects()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, project := range projectsToUpdate {
		wg.Go(func() { runner.componentService.RefreshComponentProjectInformation(project) })
	}

	wg.Wait()

	return nil
}
