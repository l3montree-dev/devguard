package workers

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/riverqueue/river"
)

type JobFactory[T any] func(payload T) river.JobArgs

type UpdateArtifactRiskAggregationArgs struct {
	ArtifactName     string
	AssetVersionName string
	AssetID          uuid.UUID
	From             time.Time
	To               time.Time
}

func (UpdateArtifactRiskAggregationArgs) Kind() string {
	return "artifact.UpdateArtifactRiskAggregation"
}

type UpdateArtifactRiskAggregationWorker struct {
	// An embedded WorkerDefaults sets up default methods to fulfill the rest of
	// the Worker interface:
	river.WorkerDefaults[UpdateArtifactRiskAggregationArgs]
	artifactRepository shared.ArtifactRepository
	statisticsService  shared.StatisticsService
}

func (w *UpdateArtifactRiskAggregationWorker) Work(ctx context.Context, job *river.Job[UpdateArtifactRiskAggregationArgs]) error {
	artifact, err := w.artifactRepository.ReadArtifact(ctx, nil, job.Args.ArtifactName, job.Args.AssetVersionName, job.Args.AssetID)
	if err != nil {
		return err
	}
	slog.Info("recalculating risk history for asset", "asset version", job.Args.AssetVersionName, "assetID", job.Args.AssetID)
	if err := w.statisticsService.UpdateArtifactRiskAggregation(ctx, nil, &artifact, job.Args.AssetID, job.Args.From, job.Args.To); err != nil {
		slog.Error("could not recalculate risk history", "err", err)
	}
	return err
}

type UpdateLicenseInformationArgs struct {
	ArtifactName     string
	AssetVersionName string
	AssetID          uuid.UUID
}

func (UpdateLicenseInformationArgs) Kind() string {
	return "artifact.UpdateLicenseInformation"
}

type UpdateLicenseInformationWorker struct {
	river.WorkerDefaults[UpdateLicenseInformationArgs]
	assetVersionRepository shared.AssetVersionRepository
	componentService       shared.ComponentService
}

func (w *UpdateLicenseInformationWorker) Work(ctx context.Context, job *river.Job[UpdateLicenseInformationArgs]) error {
	slog.Info("updating license information in background", "asset", job.Args.AssetVersionName, "assetID", job.Args.AssetID)

	assetVersion, err := w.assetVersionRepository.Read(ctx, nil, job.Args.AssetVersionName, job.Args.AssetID)
	if err != nil {
		return err
	}

	if _, err := w.componentService.GetAndSaveLicenseInformation(ctx, nil, assetVersion, &job.Args.ArtifactName, false); err != nil {
		slog.Error("could not update license information", "asset", job.Args.AssetVersionName, "assetID", job.Args.AssetID, "err", err)
		return err
	}
	slog.Info("license information updated", "asset", job.Args.AssetVersionName, "assetID", job.Args.AssetID)
	return nil
}
