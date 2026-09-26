// Copyright (C) 2026 l3montree GmbH
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

package utils

import (
	"container/list"
	"sync"
	"time"
)

// TTLCache is a concurrency-safe in-memory cache whose entries expire after a fixed
// TTL and whose total size is bounded. Because every entry lives for the same TTL,
// insertion order equals expiry order: the oldest entry is both the first to expire
// and the one evicted when the size bound is exceeded.
type TTLCache[K comparable, V any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	sizeOf  func(V) int
	now     func() time.Time
	entries map[K]*list.Element
	order   *list.List // front = oldest
	size    int
}

type ttlCacheEntry[K comparable, V any] struct {
	key      K
	value    V
	size     int
	storedAt time.Time
}

// NewTTLCache creates a cache holding entries for ttl, with the summed sizeOf of all
// entries bounded by maxSize. A nil sizeOf counts every entry as 1, bounding the
// number of entries instead.
func NewTTLCache[K comparable, V any](ttl time.Duration, maxSize int, sizeOf func(V) int) *TTLCache[K, V] {
	if sizeOf == nil {
		sizeOf = func(V) int { return 1 }
	}
	return &TTLCache[K, V]{
		ttl:     ttl,
		maxSize: maxSize,
		sizeOf:  sizeOf,
		now:     time.Now,
		entries: map[K]*list.Element{},
		order:   list.New(),
	}
}

// Get returns the value stored for key if it exists and has not expired.
func (c *TTLCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	entry := elem.Value.(*ttlCacheEntry[K, V])
	if c.now().Sub(entry.storedAt) >= c.ttl {
		c.removeElement(elem)
		var zero V
		return zero, false
	}
	return entry.value, true
}

// Set stores value for key, evicting expired and then the oldest entries until it
// fits. Values larger than maxSize are not stored.
func (c *TTLCache[K, V]) Set(key K, value V) {
	size := c.sizeOf(value)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		c.removeElement(elem)
	}
	if size > c.maxSize {
		return
	}

	// Entries are ordered oldest first, so keep dropping the front entry while it is
	// expired or while the new value does not fit yet.
	now := c.now()
	for c.order.Len() > 0 {
		oldest := c.order.Front()
		expired := now.Sub(oldest.Value.(*ttlCacheEntry[K, V]).storedAt) >= c.ttl
		if !expired && c.size+size <= c.maxSize {
			break
		}
		c.removeElement(oldest)
	}

	c.entries[key] = c.order.PushBack(&ttlCacheEntry[K, V]{key: key, value: value, size: size, storedAt: now})
	c.size += size
}

// Delete removes key from the cache.
func (c *TTLCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		c.removeElement(elem)
	}
}

// Len returns the number of stored entries, including expired ones not yet evicted.
func (c *TTLCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *TTLCache[K, V]) removeElement(elem *list.Element) {
	entry := c.order.Remove(elem).(*ttlCacheEntry[K, V])
	delete(c.entries, entry.key)
	c.size -= entry.size
}
