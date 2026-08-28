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

package dependencyfirewall

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// cacheValue is the payload stored under a cache key. releaseTime,
// contentType and digest are optional metadata a caller may want to
// round-trip alongside the raw bytes (e.g. OCI manifests need their
// upstream Content-Type and Docker-Content-Digest headers back on a hit).
type cacheValue struct {
	data        []byte
	releaseTime time.Time
	contentType string
	digest      string
}

type cacheEntry struct {
	hash        [32]byte
	size        int
	path        string
	releaseTime time.Time
	contentType string
	digest      string
	storedAt    time.Time
}

type cache struct {
	mu          sync.Mutex
	currentSize int
	// maxSize is the maximum size of the cache in bytes.
	maxSize  int
	basePath string
	cache    map[string]cacheEntry
	lru      map[string]time.Time
}

func newCache(basePath string, sizeInMB int) *cache {
	return &cache{
		currentSize: 0,
		maxSize:     sizeInMB * 1024 * 1024, // convert MB to bytes
		basePath:    basePath,
		cache:       make(map[string]cacheEntry),
		lru:         make(map[string]time.Time),
	}
}

func (c *cache) Get(key string) (cacheValue, bool) {
	c.mu.Lock()
	e, exists := c.cache[key]
	c.mu.Unlock()
	if !exists {
		return cacheValue{}, false
	}

	content, err := os.ReadFile(e.path)
	if err != nil {
		// If we can't read the file, treat it as a cache miss
		return cacheValue{}, false
	}
	// check if the hash of the content matches the stored hash
	if actual := sha256.Sum256(content); actual != e.hash {
		slog.Warn("hash mismatch for cache entry", "key", key, "expected", fmt.Sprintf("%x", e.hash), "actual", fmt.Sprintf("%x", actual))
		// remove the corrupted cache entry
		c.Remove(key)
		return cacheValue{}, false
	}

	c.mu.Lock()
	// Update the LRU map to mark this entry as recently used
	c.lru[key] = time.Now()
	c.mu.Unlock()
	return cacheValue{
		data:        content,
		releaseTime: e.releaseTime,
		contentType: e.contentType,
		digest:      e.digest,
	}, true
}

// Fresh reports whether the entry for key was stored more recently than maxAge.
// A missing entry is never fresh.
func (c *cache) Fresh(key string, maxAge time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, exists := c.cache[key]
	if !exists {
		return false
	}
	return time.Since(e.storedAt) < maxAge
}

func (c *cache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

// removeLocked removes an entry from the cache. Callers must hold c.mu.
func (c *cache) removeLocked(key string) {
	e, exists := c.cache[key]
	if !exists {
		return
	}
	// Remove the file from disk
	if err := os.Remove(e.path); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove cache file", "path", e.path, "error", err)
	}
	// Update the current size of the cache
	c.currentSize -= e.size
	// Remove from cache and LRU map
	delete(c.cache, key)
	delete(c.lru, key)
}

func (c *cache) Set(key string, v cacheValue) error {
	content := v.data
	// Check if the content size exceeds the maximum cache size
	if len(content) > c.maxSize {
		return fmt.Errorf("content size exceeds maximum cache size")
	}

	path, err := c.keyToPath(key)
	if err != nil {
		return err
	}

	if err := c.writeToDisk(path, content); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If we're overwriting an existing entry, drop its old size first
	if existing, exists := c.cache[key]; exists {
		c.currentSize -= existing.size
	}
	c.currentSize += len(content)

	// If the current size exceeds the maximum size, evict least recently used entries
	for c.currentSize > c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, t := range c.lru {
			if k == key {
				// never evict the entry we're currently inserting
				continue
			}
			if first || t.Before(oldestTime) {
				oldestTime = t
				oldestKey = k
				first = false
			}
		}
		if oldestKey == "" {
			break // No more entries to evict
		}
		c.removeLocked(oldestKey)
	}

	c.cache[key] = cacheEntry{
		hash:        sha256.Sum256(content),
		size:        len(content),
		path:        path,
		releaseTime: v.releaseTime,
		contentType: v.contentType,
		digest:      v.digest,
		storedAt:    time.Now(),
	}
	// Update the LRU map to mark this entry as recently used
	c.lru[key] = time.Now()

	return nil
}

func (c *cache) ValidateKey(key string) error {
	_, err := c.keyToPath(key)
	return err
}

func (c *cache) keyToPath(key string) (string, error) {
	// make sure we don't have any path traversal issues
	// first, replace any slashes with underscores to avoid directory traversal
	key = strings.ReplaceAll(key, "/", "_")
	cleanPath := filepath.Clean("/" + key)
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	if cleanPath == "" || cleanPath == "." {
		return "", fmt.Errorf("invalid cache path")
	}

	fullPath := filepath.Join(c.basePath, cleanPath)
	if rel, err := filepath.Rel(c.basePath, fullPath); err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("cache path traversal detected")
	}
	return fullPath, nil
}

func (c *cache) writeToDisk(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}
