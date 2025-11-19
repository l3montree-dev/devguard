package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

// testMessage for testing
type testMessage struct {
	channel database.Channel
	payload map[string]interface{}
}

func (m testMessage) GetChannel() database.Channel {
	return m.channel
}

func (m testMessage) GetPayload() map[string]interface{} {
	return m.payload
}

func TestPostgreSQLBroker(t *testing.T) {
	// Initialize test database container with SQL DB
	dbUser, dbPassword, host, port, dbName, terminate := InitSQLDatabaseContainer("../initdb.sql")
	defer terminate()

	t.Run("PublishAndSubscribe", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
		defer broker.Close()

		ctx := context.Background()
		testTopic := database.Channel("test_topic")

		// Subscribe to topic
		messagesCh, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		// Give subscriber time to start listening
		time.Sleep(100 * time.Millisecond)

		// Publish message
		testMsg := testMessage{
			channel: testTopic,
			payload: map[string]interface{}{
				"test":   "data",
				"number": 42,
			},
		}

		err = broker.Publish(ctx, testMsg)
		assert.NoError(t, err)

		// Wait for message to be received
		select {
		case receivedPayload := <-messagesCh:
			assert.Equal(t, "data", receivedPayload["test"])
			assert.Equal(t, float64(42), receivedPayload["number"])
		case <-time.After(1 * time.Second):
			t.Error("Message not received within timeout")
		}
	})

	t.Run("MultipleSubscribers", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
		defer broker.Close()

		ctx := context.Background()
		testTopic := database.Channel("multi_topic")

		// Subscribe with multiple subscribers
		subscriber1, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		subscriber2, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish message
		testMsg := testMessage{
			channel: testTopic,
			payload: map[string]interface{}{
				"multi": "test",
			},
		}

		err = broker.Publish(ctx, testMsg)
		assert.NoError(t, err)

		// Both subscribers should receive the message
		select {
		case payload1 := <-subscriber1:
			assert.Equal(t, "test", payload1["multi"])
		case <-time.After(1 * time.Second):
			t.Error("Subscriber 1 did not receive message")
		}

		select {
		case payload2 := <-subscriber2:
			assert.Equal(t, "test", payload2["multi"])
		case <-time.After(1 * time.Second):
			t.Error("Subscriber 2 did not receive message")
		}
	})

	t.Run("PolicyChangeChannel", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
		defer broker.Close()

		ctx := context.Background()

		// Subscribe to policy changes
		messagesCh, err := broker.Subscribe(database.PolicyChange)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish simple policy change message
		policyMsg := testMessage{
			channel: database.PolicyChange,
			payload: map[string]interface{}{
				"policy_id": "policy-123",
				"action":    "updated",
				"user_id":   "user-456",
			},
		}

		err = broker.Publish(ctx, policyMsg)
		assert.NoError(t, err)

		// Wait for message to be received
		select {
		case receivedPayload := <-messagesCh:
			assert.Equal(t, "policy-123", receivedPayload["policy_id"])
			assert.Equal(t, "updated", receivedPayload["action"])
			assert.Equal(t, "user-456", receivedPayload["user_id"])
		case <-time.After(1 * time.Second):
			t.Error("Policy change message not received within timeout")
		}
	})

	t.Run("GetActiveTopics", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
		defer broker.Close()

		// Initially no topics
		topics := broker.GetActiveTopics()
		assert.Empty(t, topics)

		// Subscribe to topics
		_, err = broker.Subscribe(database.Channel("topic1"))
		assert.NoError(t, err)

		_, err = broker.Subscribe(database.Channel("topic2"))
		assert.NoError(t, err)

		topics = broker.GetActiveTopics()
		assert.Len(t, topics, 2)
		assert.Contains(t, topics, database.Channel("topic1"))
		assert.Contains(t, topics, database.Channel("topic2"))
	})

	t.Run("Unsubscribe", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
		defer broker.Close()

		ctx := context.Background()
		testTopic := database.Channel("unsub_topic")

		// Subscribe
		messagesCh, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Close the broker which should close all subscriptions
		broker.Close()

		// Publish message (should not be received since broker is closed)
		testMsg := testMessage{
			channel: testTopic,
			payload: map[string]interface{}{
				"test": "unsubscribed",
			},
		}

		// This should fail or have no effect since broker is closed

		_ = broker.Publish(ctx, testMsg)
		// We don't require this to error, as the behavior when closed may vary

		// Channel should be closed
		select {
		case _, ok := <-messagesCh:
			if ok {
				t.Error("Should not receive message after broker close")
			}
			// Channel closed, which is expected
		case <-time.After(500 * time.Millisecond):
			// No message received, which is good
		}
	})
}

func TestBrokerIntegration(t *testing.T) {
	// Initialize test database container with SQL DB
	dbUser, dbPassword, host, port, dbName, terminate := InitSQLDatabaseContainer("../initdb.sql")
	defer terminate()

	broker, err := database.NewPostgreSQLBroker(dbUser, dbPassword, host, port, dbName)
	assert.NoError(t, err)
	broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages
	defer broker.Close()

	t.Run("BasicIntegration", func(t *testing.T) {
		ctx := context.Background()

		// Subscribe to policy changes to verify publication
		messagesCh, err := broker.Subscribe(database.PolicyChange)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish a simple policy change
		msg := testMessage{
			channel: database.PolicyChange,
			payload: map[string]interface{}{
				"policy_id": "policy-123",
				"action":    "updated",
				"user_id":   "user-456",
			},
		}

		err = broker.Publish(ctx, msg)
		assert.NoError(t, err)

		// Verify message received
		select {
		case receivedPayload := <-messagesCh:
			assert.Equal(t, "policy-123", receivedPayload["policy_id"])
			assert.Equal(t, "updated", receivedPayload["action"])
			assert.Equal(t, "user-456", receivedPayload["user_id"])
		case <-time.After(1 * time.Second):
			t.Error("Message not received")
		}
	})
}
