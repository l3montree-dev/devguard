// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/lib/pq"
)

type SubscribeHandler = func(ctx context.Context, payload json.RawMessage)

type PostgreSQLMessage struct {
	ID        string          `json:"id"`
	Topic     PubSubTopic     `json:"topic"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
	SenderID  string          `json:"sender_id,omitempty"` // Optional field for sender ID
}

type ListeningConnection struct {
	Conn        *pgxpool.Conn
	Subscribers []SubscribeHandler
}

// PostgreSQLBroker implements the Broker interface using PostgreSQL LISTEN/NOTIFY
type PostgreSQLBroker struct {
	db                       *pgxpool.Pool
	subscribers              map[PubSubTopic]ListeningConnection
	subscribeMux             sync.RWMutex
	wg                       sync.WaitGroup
	ID                       string      // Unique identifier for the broker instance
	shouldReceiveOwnMessages bool        // Flag to control whether to receive own messages
	listenerFailed           atomic.Bool // Set by a listener goroutine when its connection fails.
}

func (b *PostgreSQLBroker) SetShouldReceiveOwnMessages(should bool) {
	b.shouldReceiveOwnMessages = should
}

// NewPostgreSQLBroker creates a new PostgreSQL broker
func NewPostgreSQLBroker(db *pgxpool.Pool) (*PostgreSQLBroker, error) {
	broker := &PostgreSQLBroker{
		db:                       db,
		subscribers:              make(map[PubSubTopic]ListeningConnection),
		ID:                       uuid.New().String(), // Unique ID for this broker instance
		shouldReceiveOwnMessages: false,
	}

	return broker, nil
}

// Publish implements the Broker interface
func (b *PostgreSQLBroker) Publish(ctx context.Context, topic PubSubTopic, payload any) error {
	// If no payload method, serialize the entire message
	messageBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Create a PostgreSQL message with metadata
	pgMessage := PostgreSQLMessage{
		ID:        uuid.New().String(),
		Topic:     topic,
		Timestamp: time.Now(),
		SenderID:  b.ID, // Use broker ID as sender ID
		Payload:   messageBytes,
	}

	messageJSON, err := json.Marshal(pgMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal PostgreSQL message: %w", err)
	}

	query := fmt.Sprintf("NOTIFY %s, '%s'", pq.QuoteIdentifier(string(topic)), string(messageJSON))
	_, err = b.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	slog.Debug("message published", "topic", topic, "messageID", pgMessage.ID)
	return nil
}

func (b *PostgreSQLBroker) Subscribe(topic PubSubTopic, handler SubscribeHandler) error {
	b.subscribeMux.Lock()
	defer b.subscribeMux.Unlock()

	// Add channel to subscribers list
	if _, exists := b.subscribers[topic]; !exists {

		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		conn, err := b.db.Acquire(ctxWithTimeout)
		if err != nil {
			return fmt.Errorf("failed to acquire connection for listening: %w", err)
		}
		// Start listening to this topic
		if _, err = conn.Exec(context.Background(), "LISTEN "+pq.QuoteIdentifier(string(topic))); err != nil {
			return fmt.Errorf("failed to listen on topic %s: %w", topic, err)
		}
		b.wg.Go(func() {
			b.processMessages(topic, conn)
		})

		b.subscribers[topic] = ListeningConnection{
			Conn: conn,
			Subscribers: []SubscribeHandler{
				handler,
			},
		}
	}

	b.subscribers[topic] = ListeningConnection{
		Conn:        b.subscribers[topic].Conn,
		Subscribers: append(b.subscribers[topic].Subscribers, handler),
	}

	return nil
}

// processMessages handles incoming notifications in a separate goroutine
func (b *PostgreSQLBroker) processMessages(topic PubSubTopic, conn *pgxpool.Conn) {
	for {
		notification, err := conn.Conn().WaitForNotification(context.TODO())
		if err != nil {
			b.listenerFailed.Store(true)
			conn.Release()
			monitoring.AlertAndSaveInErrorLog(context.Background(), nil, monitoring.AlertContext{}, "could not listen for notifications from PostgreSQL broker", err)
			return
		}
		if notification != nil && notification.Channel == string(topic) {
			var message PostgreSQLMessage
			if err := json.Unmarshal([]byte(notification.Payload), &message); err != nil {
				slog.Error("Failed to unmarshal message", "error", err, "payload", notification.Payload)
				continue
			}

			// check if send by us
			if message.SenderID == b.ID && !b.shouldReceiveOwnMessages {
				slog.Debug("ignoring message sent by self", "messageID", message.ID, "topic", message.Topic)
				continue
			}

			b.subscribeMux.RLock()
			subscribers, exists := b.subscribers[topic]
			b.subscribeMux.RUnlock()

			if !exists {
				slog.Warn("no subscribers for topic", "topic", topic)
				continue
			}

			wg := sync.WaitGroup{}
			// Send message to all subscribers
			for _, subscriber := range subscribers.Subscribers {
				wg.Go(func() {
					subscriber(context.TODO(), message.Payload)
				})
			}

			slog.Debug("message distributed", "topic", topic, "messageID", message.ID, "subscribers", len(subscribers.Subscribers))
		}
	}
}

// IsHealthy checks if the broker is functioning properly
func (b *PostgreSQLBroker) IsHealthy() bool {
	return !b.listenerFailed.Load()
}

// GetActiveTopics returns a list of topics currently being listened to
func (b *PostgreSQLBroker) GetActiveTopics() []PubSubTopic {
	b.subscribeMux.RLock()
	defer b.subscribeMux.RUnlock()

	topics := make([]PubSubTopic, 0, len(b.subscribers))
	for topic := range b.subscribers {
		topics = append(topics, topic)
	}
	return topics
}
