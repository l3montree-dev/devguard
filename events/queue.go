package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(fx.Annotate(NewBroker, fx.As(new(Broker)))),
)

type NotifyHandler = func(ctx context.Context, payload json.RawMessage) error

type Queue struct {
	riverClient *river.Client[pgx.Tx]
	workers     *river.Workers

	mu       sync.RWMutex
	handlers map[NotifyTopic][]NotifyHandler
}

func NewQueue(lc fx.Lifecycle, dbPool *pgxpool.Pool) (*Queue, error) {
	workers := river.NewWorkers()
	client, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 25},
		},
		// the client keeps this pointer - workers added via Listen before Start are picked up
		Workers: workers,
		// allows notifying topics this instance does not listen to itself
		SkipUnknownJobCheck: true,
	})
	if err != nil {
		return nil, fmt.Errorf("could not setup river client: %w", err)
	}

	q := &Queue{
		riverClient: client,
		workers:     workers,
		handlers:    make(map[NotifyTopic][]NotifyHandler),
	}

	// fx runs OnStart hooks after all constructors and invokes - therefore after every Listen call
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return client.Start(context.Background())
		},
		OnStop: func(ctx context.Context) error {
			return client.Stop(ctx)
		},
	})

	return q, nil
}

type dynamicArgs struct {
	topic   NotifyTopic     `json:"-"`
	Payload json.RawMessage `json:"payload"`
}

func (a dynamicArgs) Kind() string {
	return string(a.topic)
}

// dynamicWorker is registered once per topic and fans out to every handler registered for that topic.
// all handlers run in the same job - if one fails, the job (and therefore every handler) is retried.
type dynamicWorker struct {
	river.WorkerDefaults[dynamicArgs]
	queue *Queue
	topic NotifyTopic
}

func (w *dynamicWorker) Work(ctx context.Context, job *river.Job[dynamicArgs]) error {
	w.queue.mu.RLock()
	handlers := w.queue.handlers[w.topic]
	w.queue.mu.RUnlock()

	var errs []error
	for _, handler := range handlers {
		if err := handler(ctx, job.Args.Payload); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *Queue) Notify(ctx context.Context, tx pgx.Tx, topic NotifyTopic, payload any, opts *NotifyOptions) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not marshal payload: %w", err)
	}
	_, err = r.riverClient.InsertTx(ctx, tx, dynamicArgs{
		topic:   topic,
		Payload: raw,
	}, opts)
	return err
}

// It must be called before the fx app is started - river does not support adding workers to a running client.
func (r *Queue) Listen(topic NotifyTopic, handler NotifyHandler) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[topic]; !exists {
		river.AddWorkerArgs(r.workers, dynamicArgs{topic: topic}, &dynamicWorker{queue: r, topic: topic})
	}
	r.handlers[topic] = append(r.handlers[topic], handler)
	return nil
}
