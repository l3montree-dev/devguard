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

import "context"

type Channel string

const (
	PolicyChange = "policyChange"
)

type Message interface {
	GetChannel() Channel
	GetPayload() map[string]any
}

type Broker interface {
	Publish(ctx context.Context, message Message) error
	Subscribe(topic Channel) (<-chan map[string]any, error)
}

type SimpleMessage struct {
	Channel Channel
	Payload map[string]any
}

func (m SimpleMessage) GetChannel() Channel {
	return m.Channel
}

func (m SimpleMessage) GetPayload() map[string]any {
	return m.Payload
}

// NewSimpleMessage creates a new SimpleMessage instance.
func NewSimpleMessage(channel Channel, payload map[string]any) *SimpleMessage {
	return &SimpleMessage{
		Channel: channel,
		Payload: payload,
	}
}
