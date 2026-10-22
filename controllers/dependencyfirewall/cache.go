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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
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
	size        int64
	path        string
	releaseTime time.Time
	contentType string
	digest      string
	storedAt    time.Time
}

type CacheStats struct {
	SizeBytes int64 `json:"sizeBytes"`
	MaxBytes  int64 `json:"maxBytes"`
	Entries   int   `json:"entries"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
}

type cache struct {
	secret      uuid.UUID
	currentSize *atomic.Int64
	hits        *atomic.Int64
	misses      *atomic.Int64
	evictions   *atomic.Int64
	basePath    string
	cache       sync.Map
	parent      *secretCaches
}

func (s *secretCaches) newCache(secret uuid.UUID, basePath string) *cache {
	c := &cache{
		currentSize: new(atomic.Int64),
		secret:      secret,
		basePath:    basePath,
		cache:       sync.Map{},
		parent:      s,
		hits:        new(atomic.Int64),
		misses:      new(atomic.Int64),
		evictions:   new(atomic.Int64),
	}
	s.caches.Store(secret, c)
	return c
}

type secretCaches struct {
	basePath    string
	sizeMB      int64
	caches      sync.Map
	currentSize *atomic.Int64
	lru         sync.Map
}

func secretCacheKey(secret uuid.UUID, key string) string {
	return fmt.Sprintf("%s:%s", secret.String(), key)
}

func newSecretCaches(baseDir string, sizeInMB int) *secretCaches {
	entries, _ := os.ReadDir(baseDir)
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(baseDir, entry.Name())); err != nil {
			slog.Warn("failed to remove entry in cache", "error", err)
		}
	}

	return &secretCaches{
		basePath:    baseDir,
		sizeMB:      int64(sizeInMB),
		lru:         sync.Map{},
		currentSize: new(atomic.Int64),
	}
}

func (s *secretCaches) markUsed(secret uuid.UUID, key string) {
	if secret == uuid.Nil {
		return
	}
	s.lru.Store(secretCacheKey(secret, key), time.Now())
}

func (s *secretCaches) removeUsed(secret uuid.UUID, key string, size int64) {
	if secret == uuid.Nil {
		return
	}
	s.lru.Delete(secretCacheKey(secret, key))
	s.currentSize.Add(-size)
}

func (s *secretCaches) increaseSizeAndMaybeEvict(newContentSize int64, secret uuid.UUID, keep string) {
	s.currentSize.Add(newContentSize)
	keepElement := secretCacheKey(secret, keep)

	for s.currentSize.Load() > s.sizeMB*1024*1024 {
		var oldestKey string
		var oldestTime time.Time
		first := true
		s.lru.Range(func(key, value any) bool {
			if key.(string) == keepElement {
				return true
			}
			if first || value.(time.Time).Before(oldestTime) {
				oldestTime = value.(time.Time)
				oldestKey = key.(string)
				first = false
			}
			return true
		})

		if oldestKey == "" {
			break
		}
		s.lru.Delete(oldestKey)
		parts := strings.SplitN(oldestKey, ":", 2)
		if len(parts) != 2 {
			slog.Warn("invalid cache key format", "key", oldestKey)
			continue
		}
		oldestSecret, err := uuid.Parse(parts[0])
		if err != nil {
			slog.Warn("failed to parse secret UUID from cache key", "key", oldestKey, "error", err)
			continue
		}
		c, err := s.forSecret(oldestSecret)
		if err != nil {
			slog.Warn("failed to get cache for secret during eviction", "secret", oldestSecret, "error", err)
			continue
		}
		c.Remove(parts[1])
	}
}

func (s *secretCaches) forSecret(secret uuid.UUID) (*cache, error) {
	if secret == uuid.Nil {
		return nil, fmt.Errorf("no secret found")
	}
	if c, ok := s.caches.Load(secret); ok {
		return c.(*cache), nil
	}
	path := filepath.Join(s.basePath, secret.String())
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}
	c, _ := s.caches.LoadOrStore(secret, s.newCache(secret, path))
	return c.(*cache), nil
}

func (s *secretCaches) Stats() CacheStats {
	totalStats := CacheStats{}
	s.caches.Range(func(_, v any) bool {
		s := v.(*cache).Stats()
		totalStats.SizeBytes += s.SizeBytes
		totalStats.MaxBytes += s.MaxBytes
		totalStats.Entries += s.Entries
		totalStats.Hits += s.Hits
		totalStats.Misses += s.Misses
		totalStats.Evictions += s.Evictions
		return true
	})
	return totalStats
}

func (c *cache) Get(key string) (cacheValue, bool) {

	e, exists := c.cache.Load(key)
	if !exists {
		c.misses.Add(1)
		return cacheValue{}, false
	}

	entry := e.(cacheEntry)

	content, err := os.ReadFile(entry.path)
	if err != nil {
		// If we can't read the file, treat it as a cache miss
		return cacheValue{}, false
	}
	// check if the hash of the content matches the stored hash
	if actual := sha256.Sum256(content); actual != entry.hash {
		slog.Warn("hash mismatch for cache entry", "key", key, "expected", fmt.Sprintf("%x", entry.hash), "actual", fmt.Sprintf("%x", actual))
		// remove the corrupted cache entry
		c.Remove(key)
		return cacheValue{}, false
	}

	// Update the LRU map to mark this entry as recently used
	c.parent.markUsed(c.secret, key)
	c.hits.Add(1)
	return cacheValue{
		data:        content,
		releaseTime: entry.releaseTime,
		contentType: entry.contentType,
		digest:      entry.digest,
	}, true
}

// Fresh reports whether the entry for key was stored more recently than maxAge.
// A missing entry is never fresh.
func (c *cache) Fresh(key string, maxAge time.Duration) bool {
	e, exists := c.cache.Load(key)
	if !exists {
		return false
	}
	return time.Since(e.(cacheEntry).storedAt) < maxAge
}

func (c *cache) Remove(key string) {
	e, exists := c.cache.Load(key)
	if !exists {
		return
	}
	entry := e.(cacheEntry)
	// Remove the file from disk
	if err := os.Remove(entry.path); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove cache file", "path", entry.path, "error", err)
	}
	// Update the current size of the cache
	c.currentSize.Add(-entry.size)
	c.evictions.Add(1)
	// we need to remove the entry from the LRU map in the parent secretCaches
	c.parent.removeUsed(c.secret, key, entry.size)
}

func (c *cache) Set(key string, v cacheValue) error {
	content := v.data
	tooLarge := int64(len(content)) > c.parent.sizeMB*1024*1024

	if tooLarge {
		return fmt.Errorf("content size exceeds maximum cache size")
	}

	path, err := c.keyToPath(key)
	if err != nil {
		return err
	}

	if err := c.writeToDisk(path, content); err != nil {
		return err
	}

	// If we're overwriting an existing entry, drop its old size first
	if existing, exists := c.cache.Load(key); exists {
		e := existing.(cacheEntry)
		c.currentSize.Add(-e.size)
		c.parent.removeUsed(c.secret, key, e.size)
	}
	c.currentSize.Add(int64(len(content)))

	c.cache.Store(key, cacheEntry{
		hash:        sha256.Sum256(content),
		size:        int64(len(content)),
		path:        path,
		releaseTime: v.releaseTime,
		contentType: v.contentType,
		digest:      v.digest,
		storedAt:    time.Now(),
	})

	c.parent.increaseSizeAndMaybeEvict(int64(len(content)), c.secret, key)
	c.parent.markUsed(c.secret, key)

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

// bypassCache reports whether the client asked for a fresh upstream response
// via "Cache-Control: no-cache" / "no-store" (or the legacy "Pragma: no-cache").
// The response is still written to the cache so later requests benefit.
func bypassCache(r *http.Request) bool {
	for _, v := range r.Header.Values("Cache-Control") {
		for _, d := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(d)) {
			case "no-cache", "no-store":
				return true
			}
		}
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Pragma")), "no-cache")
}

func (c *cache) Stats() CacheStats {
	count := 0
	c.cache.Range(func(_, _ any) bool {
		count++
		return true
	})
	return CacheStats{
		SizeBytes: c.currentSize.Load(),
		MaxBytes:  int64(c.parent.sizeMB * 1024 * 1024),
		Entries:   count,
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
	}
}
