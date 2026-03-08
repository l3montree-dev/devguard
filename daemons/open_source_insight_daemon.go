package daemons

import (
	"context"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
)

func (runner *DaemonRunner) UpdateOpenSourceInsightInformation(ctx context.Context) error {
	start := time.Now()
	defer func() {
		monitoring.UpdateOpenSourceInsightInformationDuration.Observe(time.Since(start).Minutes())
	}()

	projectsToUpdate, err := runner.componentProjectRepository.FindAllOutdatedProjects(ctx, nil)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, project := range projectsToUpdate {
		wg.Go(func() { runner.componentService.RefreshComponentProjectInformation(ctx, project) })
	}

	wg.Wait()

	return nil
}
