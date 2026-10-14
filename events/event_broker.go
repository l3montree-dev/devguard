package events

import (
	"context"
	"encoding/json"

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

	IsHealthy() bool
}

type PubSubTopic string

const (
	PolicyChange  PubSubTopic = "policyChange"
	VulnDBUpdated PubSubTopic = "vulnDBUpdated"
)

type NotifyTopic string

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
