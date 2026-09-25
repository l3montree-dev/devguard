package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newTestTTLCache(maxSize int) (*TTLCache[string, []byte], *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewTTLCache[string](time.Minute, maxSize, func(v []byte) int { return len(v) })
	c.now = func() time.Time { return now }
	return c, &now
}

func TestTTLCache(t *testing.T) {
	t.Run("returns stored values until the ttl expires", func(t *testing.T) {
		c, now := newTestTTLCache(100)
		c.Set("a", []byte("value"))

		v, ok := c.Get("a")
		assert.True(t, ok)
		assert.Equal(t, []byte("value"), v)

		*now = now.Add(time.Minute)
		_, ok = c.Get("a")
		assert.False(t, ok)
		assert.Equal(t, 0, c.Len())
	})

	t.Run("evicts the oldest entries when the size bound is exceeded", func(t *testing.T) {
		c, now := newTestTTLCache(10)
		c.Set("a", make([]byte, 4))
		*now = now.Add(time.Second)
		c.Set("b", make([]byte, 4))
		*now = now.Add(time.Second)
		c.Set("c", make([]byte, 4))

		_, ok := c.Get("a")
		assert.False(t, ok)
		_, ok = c.Get("b")
		assert.True(t, ok)
		_, ok = c.Get("c")
		assert.True(t, ok)
	})

	t.Run("evicts expired entries on set", func(t *testing.T) {
		c, now := newTestTTLCache(100)
		c.Set("a", []byte("a"))
		*now = now.Add(2 * time.Minute)
		c.Set("b", []byte("b"))
		assert.Equal(t, 1, c.Len())
	})

	t.Run("overwriting a key replaces its size and refreshes its ttl", func(t *testing.T) {
		c, now := newTestTTLCache(10)
		c.Set("a", make([]byte, 8))
		*now = now.Add(30 * time.Second)
		c.Set("a", make([]byte, 8))
		*now = now.Add(45 * time.Second)

		v, ok := c.Get("a")
		assert.True(t, ok)
		assert.Len(t, v, 8)
		assert.Equal(t, 8, c.size)
	})

	t.Run("does not store values larger than the max size", func(t *testing.T) {
		c, _ := newTestTTLCache(4)
		c.Set("a", []byte("abc"))
		c.Set("a", []byte("too large"))

		_, ok := c.Get("a")
		assert.False(t, ok)
		assert.Equal(t, 0, c.size)
	})

	t.Run("nil sizeOf bounds the number of entries", func(t *testing.T) {
		c := NewTTLCache[string, int](time.Minute, 2, nil)
		c.Set("a", 1)
		c.Set("b", 2)
		c.Set("c", 3)
		assert.Equal(t, 2, c.Len())
		_, ok := c.Get("a")
		assert.False(t, ok)
	})

	t.Run("delete removes the entry", func(t *testing.T) {
		c, _ := newTestTTLCache(10)
		c.Set("a", []byte("a"))
		c.Delete("a")
		_, ok := c.Get("a")
		assert.False(t, ok)
		assert.Equal(t, 0, c.size)
	})
}
