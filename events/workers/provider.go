package workers

import (
	"github.com/l3montree-dev/devguard/shared"
	"github.com/riverqueue/river"
)

func SetupWorkers(artifactRepository shared.ArtifactRepository, statisticsService shared.StatisticsService, assetVersionRepository shared.AssetVersionRepository, componentService shared.ComponentService) *river.Workers {
	workers := river.NewWorkers()

	// Add workers here
	if err := river.AddWorkerSafely(workers, &UpdateArtifactRiskAggregationWorker{
		artifactRepository: artifactRepository,
		statisticsService:  statisticsService,
	}); err != nil {
		panic("handle this error")
	}

	if err := river.AddWorkerSafely(workers, &UpdateLicenseInformationWorker{
		assetVersionRepository: assetVersionRepository,
		componentService:       componentService,
	}); err != nil {
		panic("handle this error")
	}
	return workers
}
