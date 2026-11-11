package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
	"github.com/robfig/cron/v3"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(fx.Annotate(NewBroker, fx.As(new(Broker)))),
)

type NotifyHandler = func(ctx context.Context, payload json.RawMessage) error

const maxAttempts = 3

const HandlerTimeout = 2 * time.Hour

const jobTimeout = HandlerTimeout + 30*time.Minute

const rescueStuckJobsAfter = jobTimeout + 30*time.Minute

// completedJobRetention bounds how far FinishedSince can look back - callers rely on it, do not lower it carelessly
const completedJobRetention = 24 * time.Hour

// QueueAssetPipeline runs the per asset pipeline steps, separated so they cannot starve the other daemons
const QueueAssetPipeline = "asset_pipeline"

type Queue struct {
	db          *pgxpool.Pool
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
			QueueAssetPipeline: {MaxWorkers: 10},
		},
		CompletedJobRetentionPeriod: completedJobRetention,
		// the client keeps this pointer - workers added via Listen before Start are picked up
		Workers:     workers,
		MaxAttempts: maxAttempts,
		// handlers are responsible for their own deadline - see dynamicWorker.Timeout
		JobTimeout:           -1,
		RescueStuckJobsAfter: rescueStuckJobsAfter,
	})
	if err != nil {
		return nil, fmt.Errorf("could not setup river client: %w", err)
	}

	q := &Queue{
		db:          dbPool,
		riverClient: client,
		workers:     workers,
		handlers:    make(map[NotifyTopic][]NotifyHandler),
	}

	// fx runs OnStart hooks after all constructors and invokes - therefore after every Listen call
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			// only start, if workers are registered, otherwise it will fail
			if len(q.handlers) == 0 {
				return nil
			}
			return client.Start(context.Background())
		},
		OnStop: func(ctx context.Context) error {
			if err := client.Stop(ctx); err != nil {
				cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return client.StopAndCancel(cancelCtx)
			}
			return nil
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

// InsertOpts are the defaults of every notification - options passed to Notify take precedence.
// An identical job is dropped while another one is still queued or running.
// completed is left out on purpose - a finished job must not block a rerun.
func (a dynamicArgs) InsertOpts() river.InsertOpts {
	queue := river.QueueDefault
	if strings.HasPrefix(string(a.topic), assetPipelineTopicPrefix) {
		queue = QueueAssetPipeline
	}
	return river.InsertOpts{
		Queue: queue,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRunning,
				rivertype.JobStateRetryable,
				rivertype.JobStateScheduled,
			},
		},
	}
}

// dynamicWorker is registered once per topic and fans out to every handler registered for that topic.
// all handlers run in the same job - if one fails, the job (and therefore every handler) is retried.
type dynamicWorker struct {
	river.WorkerDefaults[dynamicArgs]
	queue *Queue
	topic NotifyTopic
}

// river's default of one minute is way too short for most background jobs. Never return a negative value - see jobTimeout.
func (w *dynamicWorker) Timeout(*river.Job[dynamicArgs]) time.Duration {
	return jobTimeout
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
	args := dynamicArgs{
		topic:   topic,
		Payload: raw,
	}
	if tx == nil {
		_, err = r.riverClient.Insert(ctx, args, opts)
		return err
	}
	_, err = r.riverClient.InsertTx(ctx, tx, args, opts)
	return err
}

// Schedule enqueues a job for the topic according to the cron expression (standard 5 fields, e.g. "0 * * * *").
// Only the river leader schedules jobs - therefore it runs once per schedule across all instances.
// On startup or leader change the job is enqueued right away - unless it already ran within the current period
// (e.g. the current hour for an hourly schedule). This way a new instance does not wait for its first run, but deploys do not trigger a run either.
// A new job is not enqueued while the previous one is still pending, running or retrying.
func (r *Queue) Schedule(topic NotifyTopic, cronExpr string) error {
	schedule, err := cron.ParseStandard(cronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression %q for topic %s: %w", cronExpr, topic, err)
	}
	// the distance between two runs - e.g. one hour for "30 * * * *"
	next := schedule.Next(time.Now())
	period := schedule.Next(next).Sub(next)

	_, err = r.riverClient.PeriodicJobs().AddSafely(river.NewPeriodicJob(
		schedule,
		func() (river.JobArgs, *river.InsertOpts) {
			return dynamicArgs{topic: topic}, &river.InsertOpts{
				UniqueOpts: river.UniqueOpts{
					ByPeriod: period,
					// completed is included to skip the run on start if it already ran within the period.
					// discarded is not - a job which failed all attempts runs again on start.
					ByState: []rivertype.JobState{
						rivertype.JobStateCompleted,
						rivertype.JobStateAvailable,
						rivertype.JobStatePending,
						rivertype.JobStateRunning,
						rivertype.JobStateRetryable,
						rivertype.JobStateScheduled,
					},
				},
			}
		},
		&river.PeriodicJobOpts{
			ID:         string(topic),
			RunOnStart: true,
		},
	))
	return err
}

func (r *Queue) FinishedSince(ctx context.Context, topic NotifyTopic, since time.Time, match any) ([]json.RawMessage, error) {
	if since.Before(time.Now().Add(-completedJobRetention)) {
		return nil, fmt.Errorf("since %s lies before the job retention of %s", since, completedJobRetention)
	}
	filter, err := json.Marshal(map[string]any{"payload": match})
	if err != nil {
		return nil, fmt.Errorf("could not marshal match: %w", err)
	}
	if match == nil {
		filter = []byte("{}")
	}
	// kind is covered by river_job_kind, the payload containment by river_job_args_index
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT args->'payload'
		FROM river_job
		WHERE kind = $1
			AND state IN ('completed', 'discarded')
			AND finalized_at > $2
			AND args @> $3::jsonb`, string(topic), since, filter)
	if err != nil {
		return nil, fmt.Errorf("could not query finished jobs: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
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
