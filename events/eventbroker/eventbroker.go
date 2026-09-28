package eventbroker

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/events/workers"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

var subscriptions = make(map[string][]func(any) river.JobArgs)

var riverClient *river.Client[pgx.Tx]

func SetupRiver(dbPool *pgxpool.Pool, workers *river.Workers) {
	if riverClient != nil {
		return
	}

	SetupSubscriptions()

	var err error

	riverClient, err = river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 25},
		},
		Workers: workers,
	})
	if err != nil {
		monitoring.Alert("Could not setup riverClient", err)
		return
	}

	if err := riverClient.Start(context.Background()); err != nil {
		monitoring.Alert("Could not start riverClient", err)
		return
	}
}

func SetupSubscriptions() {
	SubscribeToEvent(events.ArtifactCreated, func(p events.ArtifactCreatedPayload) river.JobArgs {
		return workers.UpdateArtifactRiskAggregationArgs{
			ArtifactName:     p.ArtifactName,
			AssetVersionName: p.AssetVersionName,
			AssetID:          p.AssetID,
			From:             p.CreatedAt,
			To:               time.Now(),
		}
	})

	SubscribeToEvent(events.ArtifactCreated, func(p events.ArtifactCreatedPayload) river.JobArgs {
		return workers.UpdateLicenseInformationArgs{
			ArtifactName:     p.ArtifactName,
			AssetVersionName: p.AssetVersionName,
			AssetID:          p.AssetID,
		}
	})
}

func SubscribeToEvent[T any](event string, factory workers.JobFactory[T]) {
	subscriptions[event] = append(subscriptions[event], func(payload any) river.JobArgs {
		return factory(payload.(T))
	})
}

func PublishEvent[T any](ctx context.Context, tx pgx.Tx, event string, payload T) error {
	if subscriptions[event] == nil {
		return fmt.Errorf("Event does not exist: %s", event)
	}
	for _, factory := range subscriptions[event] {
		jobArg := factory(payload)
		var err error
		if tx != nil {
			_, err = riverClient.InsertTx(ctx, tx, jobArg, nil)
		} else {
			_, err = riverClient.Insert(ctx, jobArg, nil)
		}
		if err != nil {
			monitoring.Alert(fmt.Sprintf("could not queue job for event %s", event), err)
			continue
		}
	}
	return nil
}
