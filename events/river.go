package events

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/workers"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(
		fx.Annotate(database.GetRiverPoolConfigFromEnv, fx.ResultTags(`name:"river"`)),
	),
	fx.Provide(fx.Annotate(NewRiverInstance, fx.As(new(shared.RiverInstance)))),
	fx.Provide(workers.SetupWorkers),
	fx.Provide(
		fx.Annotate(
			SetupRiver,
			fx.ParamTags(`name:"river"`, ``),
		),
	),
)

type RiverInstance struct {
	riverClient *river.Client[pgx.Tx]
}

func NewRiverInstance(riverClient *river.Client[pgx.Tx]) *RiverInstance {
	return &RiverInstance{
		riverClient: riverClient,
	}
}

// SetupRiver builds and starts a river.Client backed by dbPool. It is provided
// via fx, which guarantees a single instance per app - callers should depend
// on *river.Client[pgx.Tx] rather than reaching into a package-level global.
func SetupRiver(dbPool *pgxpool.Pool, workers *river.Workers) (*river.Client[pgx.Tx], error) {
	client, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 25},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, fmt.Errorf("could not setup river client: %w", err)
	}

	if err := client.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("could not start river client: %w", err)
	}

	return client, nil
}

func (r RiverInstance) Publish(ctx context.Context, args river.JobArgs, opts *river.InsertOpts, errorHandler func(error)) {
	_, err := r.riverClient.Insert(ctx, args, opts)
	slog.Info("Inserted Job")
	if err != nil {
		if errorHandler != nil {
			errorHandler(err)
		} else {
			slog.Error("could not publish event and store job in river queue", "err", err, "jobArgs", args)
		}
	}
}
