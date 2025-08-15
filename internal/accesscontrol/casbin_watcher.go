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
package accesscontrol

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/casbin/casbin/v2/persist"
	"github.com/l3montree-dev/devguard/internal/pubsub"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type casbinPubSubWatcher struct {
	broker           pubsub.Broker
	callback         func(string)
	cancel           context.CancelFunc
	debouncedPublish func()
}

type policyChangePubSubMessage struct {
}

func (policyChangePubSubMessage) GetChannel() pubsub.Channel {
	return pubsub.PolicyChange
}

func (policyChangePubSubMessage) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"action": "update",
	}
}

var _ persist.Watcher = &casbinPubSubWatcher{}

func newCasbinPubSubWatcher(broker pubsub.Broker) *casbinPubSubWatcher {
	// start listening to the policy change topic
	ch, err := broker.Subscribe(pubsub.PolicyChange)
	if err != nil {
		log.Fatalf("could not subscribe to policy change topic: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	watcher := &casbinPubSubWatcher{
		broker: broker,
		cancel: cancel,
		debouncedPublish: utils.Debounce(func() {
			if err := broker.Publish(ctx, policyChangePubSubMessage{}); err != nil {
				log.Printf("could not publish policy change: %v", err)
			}
		}, 100*time.Millisecond),
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			watcher.callback("policy updated")
		}
	}()
	return watcher
}

func (w *casbinPubSubWatcher) SetUpdateCallback(callback func(string)) error {
	w.callback = callback
	return nil
}

func (w *casbinPubSubWatcher) Update() error {
	if w.callback == nil {
		return fmt.Errorf("no callback set")
	}

	w.debouncedPublish()
	return nil
}

func (w *casbinPubSubWatcher) Close() {
	if w.cancel != nil {
		w.cancel()
	}
	w.callback = nil
}
