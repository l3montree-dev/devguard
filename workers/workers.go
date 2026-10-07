package workers

import (
	"context"
	"fmt"

	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/riverqueue/river"
)

func SetupWorkers(purlComparer *scan.PurlComparer) *river.Workers {
	workers := river.NewWorkers()

	if err := river.AddWorkerSafely(workers, &VulnDBUpdateWorker{
		purlComparer: purlComparer,
	}); err != nil {
		panic(fmt.Errorf("failed to add worker to river instance: %v", err))
	}

	return workers
}

type VulnDBUpdateArgs struct {
}

func (VulnDBUpdateArgs) Kind() string {
	return "vulndb.update"
}

type VulnDBUpdateWorker struct {
	river.WorkerDefaults[VulnDBUpdateArgs]
	purlComparer *scan.PurlComparer
}

func (w *VulnDBUpdateWorker) Work(ctx context.Context, job *river.Job[VulnDBUpdateArgs]) error {
	w.purlComparer.FlushCache()
	return nil
}
