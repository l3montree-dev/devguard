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
	"encoding/json"
	"fmt"
	"log"

	"github.com/casbin/casbin/v2/persist"
	"github.com/l3montree-dev/devguard/events"
)

type casbinPubSubWatcher struct {
	broker   events.Broker
	callback func(string)
	cancel   context.CancelFunc
}

var _ persist.Watcher = &casbinPubSubWatcher{}

func newCasbinPubSubWatcher(broker events.Broker) *casbinPubSubWatcher {
	// start listening to the policy change topic
	watcher := &casbinPubSubWatcher{
		broker: broker,
	}
	if err := broker.Subscribe(events.PolicyChange, func(ctx context.Context, msg json.RawMessage) {
		watcher.callback("policy updated")
	}); err != nil {
		log.Fatalf("could not subscribe to policy change topic: %v", err)
	}

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

	ctx := context.Background()

	if err := w.broker.Publish(ctx, events.PolicyChange, nil); err != nil {
		log.Printf("could not publish policy change: %v", err)
	}
	return nil
}

func (w *casbinPubSubWatcher) Close() {
	if w.cancel != nil {
		w.cancel()
	}
	w.callback = nil
}
