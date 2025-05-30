package cache

import (
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	t.Run("new cache creation", func(t *testing.T) {
		c := New(time.Minute, 100)
		if c == nil {
			t.Error("expected non-nil cache")
		}
	})

	t.Run("set and get entry", func(t *testing.T) {
		c := New(time.Minute, 100)
		ip := "192.168.1.1"
		c.Set(ip, true)

		entry, exists := c.Get(ip)
		if !exists {
			t.Error("expected entry to exist")
		}
		if !entry.Bounced {
			t.Error("expected entry to be bounced")
		}
	})

	t.Run("expired entry", func(t *testing.T) {
		c := New(time.Millisecond, 100)
		ip := "192.168.1.1"
		c.Set(ip, true)
		time.Sleep(time.Millisecond * 2)

		_, exists := c.Get(ip)
		if exists {
			t.Error("expected entry to be expired")
		}
	})

	t.Run("entry expiration", func(t *testing.T) {
		entry := Entry{
			Bounced:   true,
			ExpiresAt: time.Now().Add(-time.Minute),
		}
		if !entry.Expired() {
			t.Error("expected entry to be expired")
		}

		entry.ExpiresAt = time.Now().Add(time.Minute)
		if entry.Expired() {
			t.Error("expected entry to not be expired")
		}
	})
}
func TestCacheSize(t *testing.T) {
	t.Run("empty cache size", func(t *testing.T) {
		c := New(time.Minute, 100)
		if size := c.Size(); size != 0 {
			t.Errorf("expected size 0, got %d", size)
		}
	})

	t.Run("cache size after adding entries", func(t *testing.T) {
		c := New(time.Minute, 100)
		c.Set("192.168.1.1", true)
		c.Set("192.168.1.2", false)

		if size := c.Size(); size != 2 {
			t.Errorf("expected size 2, got %d", size)
		}
	})

	t.Run("cache size after deletion", func(t *testing.T) {
		c := New(time.Minute, 100)
		c.Set("192.168.1.1", true)
		c.Set("192.168.1.2", false)
		c.Delete("192.168.1.1")

		if size := c.Size(); size != 1 {
			t.Errorf("expected size 1, got %d", size)
		}
	})
}
