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
package shared

import "context"

type PubSubChannel string

const (
	PolicyChange = "policyChange"
)

type PubSubMessage interface {
	GetChannel() PubSubChannel
	GetPayload() map[string]any
}

type PubSubBroker interface {
	Publish(ctx context.Context, message PubSubMessage) error
	Subscribe(topic PubSubChannel) (<-chan map[string]any, error)
}

type SimpleMessage struct {
	Channel PubSubChannel
	Payload map[string]any
}

func (m SimpleMessage) GetChannel() PubSubChannel {
	return m.Channel
}

func (m SimpleMessage) GetPayload() map[string]any {
	return m.Payload
}

// NewSimplePubSubMessage creates a new SimpleMessage instance.
func NewSimplePubSubMessage(channel PubSubChannel, payload map[string]any) *SimpleMessage {
	return &SimpleMessage{
		Channel: channel,
		Payload: payload,
	}
}
