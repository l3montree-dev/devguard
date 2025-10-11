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

package pubsub

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type PostgreSQLMessage struct {
	ID        string                 `json:"id"`
	Channel   Channel                `json:"topic"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
	SenderID  string                 `json:"sender_id,omitempty"` // Optional field for sender ID
}

func (m PostgreSQLMessage) GetChannel() Channel {
	return m.Channel
}

func (m PostgreSQLMessage) GetPayload() map[string]interface{} {
	return m.Payload
}

// PostgreSQLBroker implements the Broker interface using PostgreSQL LISTEN/NOTIFY
type PostgreSQLBroker struct {
	db                       *sql.DB
	listener                 *pq.Listener
	subscribers              map[Channel][]chan map[string]interface{}
	subscribeMux             sync.RWMutex
	ctx                      context.Context
	cancel                   context.CancelFunc
	wg                       sync.WaitGroup
	isListening              bool
	listeningMux             sync.RWMutex
	ID                       string // Unique identifier for the broker instance
	shouldReceiveOwnMessages bool   // Flag to control whether to receive own messages
}

func BrokerFactory() (Broker, error) {
	broker, err := NewPostgreSQLBroker(
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_DB"),
	)

	return broker, err
}

func (b *PostgreSQLBroker) SetShouldReceiveOwnMessages(should bool) {
	b.shouldReceiveOwnMessages = should
}

// NewPostgreSQLBroker creates a new PostgreSQL broker
func NewPostgreSQLBroker(user, password, host, port, dbname string) (*PostgreSQLBroker, error) {
	connectionString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)

	// Create database connection for publishing
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	listener := pq.NewListener(connectionString, 10*time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil {
			slog.Error("PostgreSQL listener error", "error", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())

	broker := &PostgreSQLBroker{
		db:                       db,
		listener:                 listener,
		subscribers:              make(map[Channel][]chan map[string]interface{}),
		ctx:                      ctx,
		cancel:                   cancel,
		ID:                       uuid.New().String(), // Unique ID for this broker instance
		shouldReceiveOwnMessages: false,
	}

	return broker, nil
}

// Publish implements the Broker interface
func (b *PostgreSQLBroker) Publish(ctx context.Context, message Message) error {
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
	_, err = b.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	slog.Debug("message published", "topic", topic, "messageID", pgMessage.ID)
	return nil
}

// Subscribe implements the Broker interface
func (b *PostgreSQLBroker) Subscribe(topic Channel) (<-chan map[string]interface{}, error) {
	b.subscribeMux.Lock()
	defer b.subscribeMux.Unlock()

	// Create a buffered channel for this subscriber
	ch := make(chan map[string]any, 100)

	// Add channel to subscribers list
	if _, exists := b.subscribers[topic]; !exists {
		b.subscribers[topic] = []chan map[string]interface{}{}

		// Start listening to this topic
		err := b.listener.Listen(string(topic))
		if err != nil {
			close(ch)
			return nil, fmt.Errorf("failed to listen on topic %s: %w", topic, err)
		}
		slog.Info("Started listening on topic", "topic", topic)
	}

	b.subscribers[topic] = append(b.subscribers[topic], ch)

	// Start the message processing goroutine if not already running
	b.listeningMux.Lock()
	if !b.isListening {
		b.isListening = true
		b.wg.Add(1)
		go b.processMessages()
	}
	b.listeningMux.Unlock()

	return ch, nil
}

// processMessages handles incoming notifications in a separate goroutine
func (b *PostgreSQLBroker) processMessages() {
	defer b.wg.Done()
	defer func() {
		b.listeningMux.Lock()
		b.isListening = false
		b.listeningMux.Unlock()
	}()

	for {
		select {
		case <-b.ctx.Done():
			slog.Info("Message processing stopped")
			return
		case notification := <-b.listener.Notify:
			if notification != nil {
				b.handleNotification(notification)
			}
		case <-time.After(time.Second):
			// Ping to keep connection alive
			if err := b.listener.Ping(); err != nil {
				slog.Error("Failed to ping listener", "error", err)
			}
		}
	}
}

// handleNotification processes a single notification
func (b *PostgreSQLBroker) handleNotification(notification *pq.Notification) {
	var message PostgreSQLMessage
	if err := json.Unmarshal([]byte(notification.Extra), &message); err != nil {
		slog.Error("Failed to unmarshal message", "error", err, "payload", notification.Extra)
		return
	}

	// check if send by us
	if message.SenderID == b.ID && !b.shouldReceiveOwnMessages {
		slog.Debug("ignoring message sent by self", "messageID", message.ID, "topic", message.Channel)
		return
	}

	topic := Channel(notification.Channel)

	b.subscribeMux.RLock()
	subscribers, exists := b.subscribers[topic]
	b.subscribeMux.RUnlock()

	if !exists {
		slog.Warn("no subscribers for topic", "topic", topic)
		return
	}

	// Send message to all subscribers
	for _, subscriber := range subscribers {
		select {
		case subscriber <- message.Payload:
			// Message sent successfully
		default:
			// Channel is full, skip this subscriber
			slog.Warn("subscriber channel full, dropping message", "topic", topic, "messageID", message.ID)
		}
	}

	slog.Debug("message distributed", "topic", topic, "messageID", message.ID, "subscribers", len(subscribers))
}

// Close stops the broker and cleans up resources
func (b *PostgreSQLBroker) Close() error {
	slog.Info("Closing PostgreSQL broker")

	// Cancel context to stop processing
	b.cancel()

	b.wg.Wait()

	b.subscribeMux.Lock()
	for topic, subscribers := range b.subscribers {
		for _, ch := range subscribers {
			close(ch)
		}
		delete(b.subscribers, topic)
	}
	b.subscribeMux.Unlock()

	if err := b.listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener: %w", err)
	}

	// Close the database connection
	if b.db != nil {
		if err := b.db.Close(); err != nil {
			return fmt.Errorf("failed to close database connection: %w", err)
		}
	}

	slog.Info("PostgreSQL broker closed successfully")
	return nil
}

// IsHealthy checks if the broker is functioning properly
func (b *PostgreSQLBroker) IsHealthy() bool {
	if b.db == nil {
		return false
	}
	if err := b.db.Ping(); err != nil {
		return false
	}
	return b.listener.Ping() == nil
}

// GetActiveTopics returns a list of topics currently being listened to
func (b *PostgreSQLBroker) GetActiveTopics() []Channel {
	b.subscribeMux.RLock()
	defer b.subscribeMux.RUnlock()

	topics := make([]Channel, 0, len(b.subscribers))
	for topic := range b.subscribers {
		topics = append(topics, topic)
	}
	return topics
}
