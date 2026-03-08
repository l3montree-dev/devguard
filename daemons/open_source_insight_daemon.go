package daemons

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func (runner *DaemonRunner) UpdateOpenSourceInsightInformation(ctx context.Context) error {
	ctx, span := otel.Tracer("devguard.daemon").Start(ctx, "daemon.open-source-insight")
	defer span.End()

	projectsToUpdate, err := runner.componentProjectRepository.FindAllOutdatedProjects(ctx, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetAttributes(attribute.Int("projects.count", len(projectsToUpdate)))

	var wg sync.WaitGroup
	for _, project := range projectsToUpdate {
		wg.Go(func() { runner.componentService.RefreshComponentProjectInformation(ctx, project) })
	}

	wg.Wait()

	return nil
}
