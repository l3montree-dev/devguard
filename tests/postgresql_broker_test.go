package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/shared"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

// testMessage for testing
type testMessage struct {
	channel shared.PubSubChannel
	payload map[string]any
}

func (m testMessage) GetChannel() shared.PubSubChannel {
	return m.channel
}

func (m testMessage) GetPayload() map[string]any {
	return m.payload
}

func TestPostgreSQLBroker(t *testing.T) {
	// Initialize test database container with SQL DB
	db, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	t.Run("PublishAndSubscribe", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(db)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		ctx := context.Background()
		testTopic := shared.PubSubChannel("test_topic")

		// Subscribe to topic
		messagesCh, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		// Give subscriber time to start listening
		time.Sleep(100 * time.Millisecond)

		// Publish message
		testMsg := testMessage{
			channel: testTopic,
			payload: map[string]any{
				"test":   "data",
				"number": 42,
			},
		}

		err = broker.Publish(ctx, testMsg)
		assert.NoError(t, err)

		var received bool
		// Wait for message to be received
		select {
		case receivedPayload := <-messagesCh:
			received = true
			assert.Equal(t, "data", receivedPayload["test"])
			assert.Equal(t, float64(42), receivedPayload["number"])
		case <-time.After(1 * time.Second):
			t.Error("Message not received within timeout")
		}

		assert.True(t, received, "Expected to receive a message")
	})

	t.Run("MultipleSubscribers", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(db)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		ctx := context.Background()
		testTopic := shared.PubSubChannel("multi_topic")

		// Subscribe with multiple subscribers
		subscriber1, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		subscriber2, err := broker.Subscribe(testTopic)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish message
		testMsg := testMessage{
			channel: testTopic,
			payload: map[string]any{
				"multi": "test",
			},
		}

		err = broker.Publish(ctx, testMsg)
		assert.NoError(t, err)

		var received1, received2 bool
		// Both subscribers should receive the message
		select {
		case payload1 := <-subscriber1:
			received1 = true
			assert.Equal(t, "test", payload1["multi"])
		case <-time.After(1 * time.Second):
			t.Error("Subscriber 1 did not receive message")
		}

		select {
		case payload2 := <-subscriber2:
			received2 = true
			assert.Equal(t, "test", payload2["multi"])
		case <-time.After(1 * time.Second):
			t.Error("Subscriber 2 did not receive message")
		}

		assert.True(t, received1, "Subscriber 1 should have received the message")
		assert.True(t, received2, "Subscriber 2 should have received the message")
	})

	t.Run("PolicyChangeChannel", func(t *testing.T) {
		broker, err := database.NewPostgreSQLBroker(db)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		ctx := context.Background()

		// Subscribe to policy changes
		messagesCh, err := broker.Subscribe(shared.PolicyChange)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish simple policy change message
		policyMsg := testMessage{
			channel: shared.PolicyChange,
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
		broker, err := database.NewPostgreSQLBroker(db)
		assert.NoError(t, err)
		broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

		// Initially no topics
		topics := broker.GetActiveTopics()
		assert.Empty(t, topics)

		// Subscribe to topics
		_, err = broker.Subscribe(shared.PubSubChannel("topic1"))
		assert.NoError(t, err)

		_, err = broker.Subscribe(shared.PubSubChannel("topic2"))
		assert.NoError(t, err)

		topics = broker.GetActiveTopics()
		assert.Len(t, topics, 2)
		assert.Contains(t, topics, shared.PubSubChannel("topic1"))
		assert.Contains(t, topics, shared.PubSubChannel("topic2"))
	})
}

func TestBrokerIntegration(t *testing.T) {
	// Initialize test database container with SQL DB
	db, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	broker, err := database.NewPostgreSQLBroker(db)
	assert.NoError(t, err)
	broker.SetShouldReceiveOwnMessages(true) // Enable receiving own messages

	t.Run("BasicIntegration", func(t *testing.T) {
		ctx := context.Background()

		// Subscribe to policy changes to verify publication
		messagesCh, err := broker.Subscribe(shared.PolicyChange)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Publish a simple policy change
		msg := testMessage{
			channel: shared.PolicyChange,
			payload: map[string]any{
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
