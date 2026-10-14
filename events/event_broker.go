package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"go.uber.org/fx"
)

type NotifyOptions = river.InsertOpts

// combines pub/sub and notify/listen
type Broker interface {
	// pub/sub - broadcast to all instances of devguard
	Publish(ctx context.Context, topic PubSubTopic, payload any) error
	Subscribe(topic PubSubTopic, handler SubscribeHandler) error

	// deliver exactly once - only a single instance of devguard will receive the message and execute the handler.
	Notify(ctx context.Context, tx pgx.Tx, topic NotifyTopic, payload any, opts *NotifyOptions) error
	Listen(topic NotifyTopic, handler NotifyHandler) error
	// Schedule notifies the topic according to the cron expression - exactly once across all instances.
	Schedule(topic NotifyTopic, cronExpr string) error
	// FinishedSince returns the distinct payloads of the jobs of the topic which completed or were discarded after since.
	// match filters by payload containment (jsonb @>) - nil matches every job.
	// finished jobs are only kept for completedJobRetention, since must not lie further back.
	FinishedSince(ctx context.Context, topic NotifyTopic, since time.Time, match any) ([]json.RawMessage, error)

	IsHealthy() bool
}

type PubSubTopic string

const (
	PolicyChange  PubSubTopic = "policyChange"
	VulnDBUpdated PubSubTopic = "vulnDBUpdated"
)

type NotifyTopic string

// Job topics. They are persisted as river job kinds - do not rename while jobs of the old name may still be queued.
const (
	TopicVEXRuleRecommendations       NotifyTopic = "daemon.vexRuleRecommendations"
	TopicCleanupOrphanedRecords       NotifyTopic = "daemon.cleanupOrphanedRecords"
	TopicSBOMGarbageCollection        NotifyTopic = "daemon.sbomGarbageCollection"
	TopicOpenSourceInsights           NotifyTopic = "daemon.openSourceInsights"
	TopicExternalEntityGarbage        NotifyTopic = "daemon.externalEntityGarbage"
	TopicAssetPipeline                NotifyTopic = "daemon.assetPipeline"
	TopicVulnDB                       NotifyTopic = "daemon.vulnDB"
	TopicScan                         NotifyTopic = "daemon.scan"
	TopicFixedVersions                NotifyTopic = "daemon.fixedVersions"
	TopicDirectDependencyFixedVersion NotifyTopic = "daemon.directDependencyFixedVersion"

	// asset pipeline steps - one job per asset and step, the payload carries the asset id
	TopicPipelineDeleteOldAssetVersions   NotifyTopic = "pipeline.deleteOldAssetVersions"
	TopicPipelineSyncUpstream             NotifyTopic = "pipeline.syncUpstream"
	TopicPipelineApplyVEXRules            NotifyTopic = "pipeline.applyVEXRules"
	TopicPipelineRecalculateRisk          NotifyTopic = "pipeline.recalculateRisk"
	TopicPipelineResolveFixedVersions     NotifyTopic = "pipeline.resolveFixedVersions"
	TopicPipelineSyncTickets              NotifyTopic = "pipeline.syncTickets"
	TopicPipelineResolveTicketDifferences NotifyTopic = "pipeline.resolveTicketDifferences"
	TopicPipelineCollectStats             NotifyTopic = "pipeline.collectStats"
)

type EventBrokerImpl struct {
	*PostgreSQLBroker
	*Queue
}

type EventBrokerStub struct {
}

func (EventBrokerStub) Publish(ctx context.Context, topic PubSubTopic, payload any) error {
	return nil
}

func (EventBrokerStub) Subscribe(topic PubSubTopic, handler func(ctx context.Context, payload json.RawMessage)) error {
	return nil
}

func (EventBrokerStub) Notify(ctx context.Context, tx pgx.Tx, topic NotifyTopic, payload any, opts *NotifyOptions) error {
	return nil
}

func (EventBrokerStub) Listen(topic NotifyTopic, handler NotifyHandler) error {
	return nil
}

func (EventBrokerStub) Schedule(topic NotifyTopic, cronExpr string) error {
	return nil
}

func (EventBrokerStub) FinishedSince(ctx context.Context, topic NotifyTopic, since time.Time, match any) ([]json.RawMessage, error) {
	return nil, nil
}

func (EventBrokerStub) IsHealthy() bool {
	return true
}

var BrokerStub = EventBrokerStub{}

func NewBroker(lc fx.Lifecycle, db *pgxpool.Pool) (*EventBrokerImpl, error) {
	broker, err := NewPostgreSQLBroker(db)
	if err != nil {
		return nil, err
	}
	queue, err := NewQueue(lc, db)
	if err != nil {
		return nil, err
	}
	return &EventBrokerImpl{PostgreSQLBroker: broker, Queue: queue}, nil
}

var _ Broker = (*EventBrokerImpl)(nil)
var _ Broker = EventBrokerStub{}
