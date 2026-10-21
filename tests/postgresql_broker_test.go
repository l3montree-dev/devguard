package tests

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/events"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recorder collects the payloads delivered to a subscribe handler.
type recorder struct {
	mu       sync.Mutex
	payloads []map[string]any
}

func (r *recorder) handle(_ context.Context, payload json.RawMessage) {
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads = append(r.payloads, m)
}

func (r *recorder) first() (map[string]any, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.payloads) == 0 {
		return nil, false
	}
	return r.payloads[0], true
}

// waitForMessage blocks until the recorder received a message and returns it.
func (r *recorder) waitForMessage(t *testing.T) map[string]any {
	t.Helper()
	require.Eventually(t, func() bool {
		_, ok := r.first()
		return ok
	}, time.Second, 10*time.Millisecond, "message not received within timeout")
	m, _ := r.first()
	return m
}

// releaseListeners terminates the connections a test's brokers hold for LISTEN, so they return to the
// (small) shared pool. The broker has no Close - it releases a listener connection once it fails.
func releaseListeners(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	t.Cleanup(func() {
		_, err := db.Exec(context.Background(), `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = current_database()
				AND pid <> pg_backend_pid()
				AND query LIKE 'LISTEN %'
		`)
		assert.NoError(t, err)
		// give the broker goroutines time to notice and release their connections
		time.Sleep(200 * time.Millisecond)
	})
}

func TestPostgreSQLBroker(t *testing.T) {
	// Initialize test database container with SQL DB
	db, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	t.Run("PublishAndSubscribe", func(t *testing.T) {
		releaseListeners(t, db)
		broker, err := events.NewPostgreSQLBroker(db)
		require.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		testTopic := events.PubSubTopic("test_topic")

		rec := &recorder{}
		require.NoError(t, broker.Subscribe(testTopic, rec.handle))

		err = broker.Publish(context.Background(), testTopic, map[string]any{
			"test":   "data",
			"number": 42,
		})
		require.NoError(t, err)

		received := rec.waitForMessage(t)
		assert.Equal(t, "data", received["test"])
		assert.Equal(t, float64(42), received["number"])
	})

	t.Run("MultipleSubscribers", func(t *testing.T) {
		releaseListeners(t, db)
		broker, err := events.NewPostgreSQLBroker(db)
		require.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		testTopic := events.PubSubTopic("multi_topic")

		rec1, rec2 := &recorder{}, &recorder{}
		require.NoError(t, broker.Subscribe(testTopic, rec1.handle))
		require.NoError(t, broker.Subscribe(testTopic, rec2.handle))

		err = broker.Publish(context.Background(), testTopic, map[string]any{"multi": "test"})
		require.NoError(t, err)

		// Both subscribers should receive the message
		assert.Equal(t, "test", rec1.waitForMessage(t)["multi"])
		assert.Equal(t, "test", rec2.waitForMessage(t)["multi"])
	})

	t.Run("PolicyChangeTopic", func(t *testing.T) {
		releaseListeners(t, db)
		broker, err := events.NewPostgreSQLBroker(db)
		require.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		rec := &recorder{}
		require.NoError(t, broker.Subscribe(events.PolicyChange, rec.handle))

		err = broker.Publish(context.Background(), events.PolicyChange, map[string]any{
			"policy_id": "policy-123",
			"action":    "updated",
			"user_id":   "user-456",
		})
		require.NoError(t, err)

		received := rec.waitForMessage(t)
		assert.Equal(t, "policy-123", received["policy_id"])
		assert.Equal(t, "updated", received["action"])
		assert.Equal(t, "user-456", received["user_id"])
	})

	t.Run("OwnMessagesAreIgnoredByDefault", func(t *testing.T) {
		releaseListeners(t, db)
		broker, err := events.NewPostgreSQLBroker(db)
		require.NoError(t, err)

		topic := events.PubSubTopic("own_messages_topic")

		rec := &recorder{}
		require.NoError(t, broker.Subscribe(topic, rec.handle))

		require.NoError(t, broker.Publish(context.Background(), topic, map[string]any{"a": "b"}))

		time.Sleep(300 * time.Millisecond)
		_, ok := rec.first()
		assert.False(t, ok, "broker must not receive its own messages by default")
	})

	t.Run("GetActiveTopics", func(t *testing.T) {
		releaseListeners(t, db)
		broker, err := events.NewPostgreSQLBroker(db)
		require.NoError(t, err)

		// Initially no topics
		assert.Empty(t, broker.GetActiveTopics())

		noop := func(context.Context, json.RawMessage) {}
		require.NoError(t, broker.Subscribe(events.PubSubTopic("topic1"), noop))
		require.NoError(t, broker.Subscribe(events.PubSubTopic("topic2"), noop))

		topics := broker.GetActiveTopics()
		assert.Len(t, topics, 2)
		assert.Contains(t, topics, events.PubSubTopic("topic1"))
		assert.Contains(t, topics, events.PubSubTopic("topic2"))
	})
}

func TestBrokerIntegration(t *testing.T) {
	// Initialize test database container with SQL DB
	db, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	broker, err := events.NewPostgreSQLBroker(db)
	require.NoError(t, err)
	broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

	t.Run("BasicIntegration", func(t *testing.T) {
		rec := &recorder{}
		require.NoError(t, broker.Subscribe(events.PolicyChange, rec.handle))

		err := broker.Publish(context.Background(), events.PolicyChange, map[string]any{
			"policy_id": "policy-123",
			"action":    "updated",
			"user_id":   "user-456",
		})
		require.NoError(t, err)

		received := rec.waitForMessage(t)
		assert.Equal(t, "policy-123", received["policy_id"])
		assert.Equal(t, "updated", received["action"])
		assert.Equal(t, "user-456", received["user_id"])
	})

	t.Run("ListenerFailureMarksBrokerUnhealthy", func(t *testing.T) {
		ctx := context.Background()
		topic := events.PubSubTopic("listener_health_check")

		require.NoError(t, broker.Subscribe(topic, func(context.Context, json.RawMessage) {}))
		require.True(t, broker.IsHealthy())

		var terminated bool
		err := db.QueryRow(ctx, `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = current_database()
				AND pid <> pg_backend_pid()
				AND query = $1
			LIMIT 1
		`, `LISTEN "listener_health_check"`).Scan(&terminated)
		require.NoError(t, err)
		require.True(t, terminated, "listener database connection was not terminated")

		require.Eventually(t, func() bool {
			return !broker.IsHealthy()
		}, 5*time.Second, 10*time.Millisecond)
	})
}
