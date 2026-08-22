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
	"os"
	"testing"
)

func TestCacheSetAndGet(t *testing.T) {
	c := newCache(t.TempDir(), 10)
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
	dir := t.TempDir()
	c := newCache(dir, 10)
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
	c := newCache(dir, 10)

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
	dir := t.TempDir()
	// 1MB cache; each entry below is ~600KB so a third insert forces eviction.
	c := newCache(dir, 1)
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
