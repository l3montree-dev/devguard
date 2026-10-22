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
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestSecretCachesReturnsSameCacheForSameSecret(t *testing.T) {
	s := newSecretCaches(t.TempDir(), 10)
	secret := uuid.New()

	first, err := s.forSecret(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := s.forSecret(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first != second {
		t.Fatal("expected the same cache instance for the same secret")
	}
}

func TestSecretCachesReturnsDifferentCacheForDifferentSecrets(t *testing.T) {
	s := newSecretCaches(t.TempDir(), 10)
	secret1 := uuid.New()
	secret2 := uuid.New()

	first, err := s.forSecret(secret1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := s.forSecret(secret2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first == second {
		t.Fatal("expected different cache instance for the two secrets")
	}
}

func TestSecretCachesIsolatesEntriesBetweenSecrets(t *testing.T) {
	s := newSecretCaches(t.TempDir(), 10)

	secretA, err := s.forSecret(uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secretB, err := s.forSecret(uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := secretA.Set("pkg", cacheValue{data: []byte("secret a content")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := secretB.Get("pkg"); ok {
		t.Fatal("expected cache miss for other secret")
	}
}

func TestCacheSetAndGet(t *testing.T) {
	s := &secretCaches{
		basePath:    "",
		sizeMB:      10,
		lru:         sync.Map{},
		currentSize: new(atomic.Int64),
	}
	c := s.newCache(uuid.New(), t.TempDir())
	data := []byte("test package content")

	if err := c.Set("pkg", cacheValue{data: data}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry, ok := c.Get("pkg")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(entry.data) != string(data) {
		t.Fatalf("expected %q, got %q", data, entry.data)
	}
}

func TestCacheGetDetectsCorruption(t *testing.T) {
	s := &secretCaches{
		basePath:    "",
		sizeMB:      10,
		lru:         sync.Map{},
		currentSize: new(atomic.Int64),
	}
	c := s.newCache(uuid.New(), t.TempDir())
	data := []byte("original package content")

	if err := c.Set("pkg", cacheValue{data: data}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path, err := c.keyToPath("pkg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered package content"), 0644); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := c.Get("pkg"); ok {
		t.Fatal("expected cache miss for tampered data")
	}

	// The corrupted entry should have been evicted, including its file on disk.
	if _, ok := c.Get("pkg"); ok {
		t.Fatal("expected corrupted entry to stay evicted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected corrupted file to be removed, stat error: %v", err)
	}
}

func TestCacheRemove(t *testing.T) {
	dir := t.TempDir()

	s := &secretCaches{
		basePath:    "",
		sizeMB:      10,
		lru:         sync.Map{},
		currentSize: new(atomic.Int64),
	}
	c := s.newCache(uuid.New(), dir)

	if err := c.Set("malicious-pkg", cacheValue{data: []byte("fake malicious content")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path, err := c.keyToPath("malicious-pkg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist before removal: %v", err)
	}

	c.Remove("malicious-pkg")

	if _, ok := c.Get("malicious-pkg"); ok {
		t.Fatal("expected cache miss after removal")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file to be removed, stat error: %v", err)
	}
}

func TestCacheEvictsLeastRecentlyUsedWhenOverCapacity(t *testing.T) {
	s := &secretCaches{
		basePath:    "",
		sizeMB:      1, // 1MB cache
		lru:         sync.Map{},
		currentSize: new(atomic.Int64),
	}
	dir := t.TempDir()
	// 1MB cache; each entry below is ~600KB so a third insert forces eviction.
	c := s.newCache(uuid.New(), dir)
	chunk := make([]byte, 600*1024)

	if err := c.Set("a", cacheValue{data: chunk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Set("b", cacheValue{data: chunk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := c.Get("a"); ok {
		t.Fatal("expected least recently used entry to have been evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("expected most recently inserted entry to survive")
	}
}

func TestCacheBudgetIsSharedAcrossAllSecrets(t *testing.T) {
	s := newSecretCaches(t.TempDir(), 1) // 1MB shared across every secret

	a, err := s.forSecret(uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := s.forSecret(uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	chunk := make([]byte, 600*1024)
	if err := a.Set("a", cacheValue{data: chunk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The second secret pushes the shared budget over capacity, so the entry
	// of the *other* secret has to be evicted.
	if err := b.Set("b", cacheValue{data: chunk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := a.Get("a"); ok {
		t.Fatal("expected entry of the other secret to be evicted by the shared budget")
	}
	if _, ok := b.Get("b"); !ok {
		t.Fatal("expected most recently inserted entry to survive")
	}

	total := s.Stats().SizeBytes
	if max := s.sizeMB * 1024 * 1024; total > max {
		t.Fatalf("total size across all caches %d exceeds shared maximum %d", total, max)
	}
	if want := int64(len(chunk)); total != want {
		t.Fatalf("expected total size across all caches to be %d, got %d", want, total)
	}
}

func TestBypassCache(t *testing.T) {
	tests := []struct {
		name   string
		header map[string]string
		want   bool
	}{
		{"none", nil, false},
		{"no-cache", map[string]string{"Cache-Control": "no-cache"}, true},
		{"no-store mixed case", map[string]string{"Cache-Control": "max-age=0, No-Store"}, true},
		{"max-age only", map[string]string{"Cache-Control": "max-age=60"}, false},
		{"pragma", map[string]string{"Pragma": "no-cache"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.header {
				r.Header.Set(k, v)
			}
			if got := bypassCache(r); got != tt.want {
				t.Fatalf("bypassCache() = %v, want %v", got, tt.want)
			}
		})
	}
}
