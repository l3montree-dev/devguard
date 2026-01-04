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

package database

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/lib/pq"
)

type PostgreSQLMessage struct {
	ID        string                 `json:"id"`
	Channel   shared.PubSubChannel   `json:"topic"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
	SenderID  string                 `json:"sender_id,omitempty"` // Optional field for sender ID
}

func (m PostgreSQLMessage) GetChannel() shared.PubSubChannel {
	return m.Channel
}

func (m PostgreSQLMessage) GetPayload() map[string]interface{} {
	return m.Payload
}

type ListeningConnection struct {
	Conn        *pgxpool.Conn
	Subscribers []chan map[string]interface{}
}

// PostgreSQLBroker implements the Broker interface using PostgreSQL LISTEN/NOTIFY
type PostgreSQLBroker struct {
	db                       *pgxpool.Pool
	subscribers              map[shared.PubSubChannel]ListeningConnection
	subscribeMux             sync.RWMutex
	wg                       sync.WaitGroup
	ID                       string // Unique identifier for the broker instance
	shouldReceiveOwnMessages bool   // Flag to control whether to receive own messages
}

func (b *PostgreSQLBroker) SetShouldReceiveOwnMessages(should bool) {
	b.shouldReceiveOwnMessages = should
}

// NewPostgreSQLBroker creates a new PostgreSQL broker
func NewPostgreSQLBroker(db *pgxpool.Pool) (*PostgreSQLBroker, error) {
	broker := &PostgreSQLBroker{
		db:                       db,
		subscribers:              make(map[shared.PubSubChannel]ListeningConnection),
		ID:                       uuid.New().String(), // Unique ID for this broker instance
		shouldReceiveOwnMessages: false,
	}

	return broker, nil
}

// Publish implements the Broker interface
func (b *PostgreSQLBroker) Publish(ctx context.Context, message shared.PubSubMessage) error {
	topic := message.GetChannel()

	// Create a PostgreSQL message with metadata
	pgMessage := PostgreSQLMessage{
		ID:        uuid.New().String(),
		Channel:   topic,
		Timestamp: time.Now(),
		SenderID:  b.ID, // Use broker ID as sender ID
	}

	// Extract payload from the message if it has one
	if payloadMsg, ok := message.(interface{ GetPayload() map[string]interface{} }); ok {
		pgMessage.Payload = payloadMsg.GetPayload()
	} else {
		// If no payload method, serialize the entire message
		messageBytes, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}

		var messageMap map[string]any
		if err := json.Unmarshal(messageBytes, &messageMap); err != nil {
			return fmt.Errorf("failed to unmarshal message to map: %w", err)
		}
		pgMessage.Payload = messageMap
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

// Subscribe implements the Broker interface
func (b *PostgreSQLBroker) Subscribe(topic shared.PubSubChannel) (<-chan map[string]interface{}, error) {
	b.subscribeMux.Lock()
	defer b.subscribeMux.Unlock()

	// Create a buffered channel for this subscriber
	ch := make(chan map[string]any, 100)

	// Add channel to subscribers list
	if _, exists := b.subscribers[topic]; !exists {

		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		conn, err := b.db.Acquire(ctxWithTimeout)
		if err != nil {
			close(ch)
			return nil, fmt.Errorf("failed to acquire connection for listening: %w", err)
		}
		// Start listening to this topic
		if _, err = conn.Exec(context.Background(), "LISTEN "+pq.QuoteIdentifier(string(topic))); err != nil {
			close(ch)
			return nil, fmt.Errorf("failed to listen on topic %s: %w", topic, err)
		}
		b.wg.Go(func() {
			b.processMessages(topic, conn)
		})

		b.subscribers[topic] = ListeningConnection{
			Conn: conn,
			Subscribers: []chan map[string]interface{}{
				ch,
			},
		}
	}

	b.subscribers[topic] = ListeningConnection{
		Conn:        b.subscribers[topic].Conn,
		Subscribers: append(b.subscribers[topic].Subscribers, ch),
	}

	return ch, nil
}

// processMessages handles incoming notifications in a separate goroutine
func (b *PostgreSQLBroker) processMessages(topic shared.PubSubChannel, conn *pgxpool.Conn) {
	for {
		notification, err := conn.Conn().WaitForNotification(context.TODO())
		if err != nil {
			conn.Release()
			monitoring.Alert("could not listen for notifications from PostgreSQL broker", err)
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
				slog.Debug("ignoring message sent by self", "messageID", message.ID, "topic", message.Channel)
				continue
			}

			b.subscribeMux.RLock()
			subscribers, exists := b.subscribers[topic]
			b.subscribeMux.RUnlock()

			if !exists {
				slog.Warn("no subscribers for topic", "topic", topic)
				continue
			}

			// Send message to all subscribers
			for _, subscriber := range subscribers.Subscribers {
				select {
				case subscriber <- message.Payload:
					// Message sent successfully
				default:
					// shared.PubSubChannel is full, skip this subscriber
					slog.Warn("subscriber channel full, dropping message", "topic", topic, "messageID", message.ID)
				}
			}

			slog.Debug("message distributed", "topic", topic, "messageID", message.ID, "subscribers", len(subscribers.Subscribers))
		}
	}
}

// IsHealthy checks if the broker is functioning properly
func (b *PostgreSQLBroker) IsHealthy() bool {
	// check if all listening connections are still alive
	b.subscribeMux.RLock()
	defer b.subscribeMux.RUnlock()

	for topic, listeningConn := range b.subscribers {
		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := listeningConn.Conn.Ping(ctxWithTimeout); err != nil {
			slog.Error("listening connection is not healthy", "topic", topic, "error", err)
			return false
		}
	}
	return true
}

// GetActiveTopics returns a list of topics currently being listened to
func (b *PostgreSQLBroker) GetActiveTopics() []shared.PubSubChannel {
	b.subscribeMux.RLock()
	defer b.subscribeMux.RUnlock()

	topics := make([]shared.PubSubChannel, 0, len(b.subscribers))
	for topic := range b.subscribers {
		topics = append(topics, topic)
	}
	return topics
}
