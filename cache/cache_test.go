package cache

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func ptr[T any](v T) *T {
	return &v
}

func TestDecisionCache(t *testing.T) {
	c := New[models.Decision]()
	if c.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", c.Size())
	}

	ip := "192.168.1.1"
	decision := models.Decision{
		ID:       1,
		Origin:   ptr("test"),
		Type:     ptr("ban"),
		Value:    &ip,
		Duration: ptr(time.Hour.String()),
		Scenario: ptr("test"),
	}
	c.Set(ip, decision)
	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}
	got, ok := c.Get(ip)
	if !ok {
		t.Errorf("expected to find entry for %s", ip)
	}
	if *got.Value != ip {
		t.Errorf("expected ip %s, got %s", ip, *got.Value)
	}
	c.Delete(ip)
	if c.Size() != 0 {
		t.Errorf("expected empty cache after delete, got size %d", c.Size())
	}

	_, ok = c.Get(ip)
	if ok {
		t.Errorf("expected no entry for %s after delete", ip)
	}
}

func TestCaptchaCache(t *testing.T) {
	c := New[time.Time]()
	if c.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", c.Size())
	}

	ip := "192.168.1.1"
	expiry := time.Now().Add(time.Hour)
	c.Set(ip, expiry)
	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}

	got, ok := c.Get(ip)
	if !ok {
		t.Errorf("expected to find entry for %s", ip)
	}
	if !got.Equal(expiry) {
		t.Errorf("expected expiry %v, got %v", expiry, got)
	}

	c.Delete(ip)
	if c.Size() != 0 {
		t.Errorf("expected empty cache after delete, got size %d", c.Size())
	}

	_, ok = c.Get(ip)
	if ok {
		t.Errorf("expected no entry for %s after delete", ip)
	}
}

func TestCacheKeys(t *testing.T) {
	c := New[string]()

	if len(c.Keys()) != 0 {
		t.Errorf("expected no keys in empty cache, got %d", len(c.Keys()))
	}

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	keys := c.Keys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	sort.Strings(keys)
	expected := []string{"key1", "key2", "key3"}
	if !reflect.DeepEqual(keys, expected) {
		t.Errorf("expected keys %v, got %v", expected, keys)
	}

	c.Delete("key2")
	keys = c.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys after delete, got %d", len(keys))
	}

	sort.Strings(keys)
	expected = []string{"key1", "key3"}
	if !reflect.DeepEqual(keys, expected) {
		t.Errorf("expected keys %v after delete, got %v", expected, keys)
	}
}

func TestWithCleanupInterval(t *testing.T) {
	interval := 10 * time.Minute
	c := New(WithCleanupInterval[string](interval))

	if c.cleanupInterval != interval {
		t.Errorf("expected cleanup interval %v, got %v", interval, c.cleanupInterval)
	}
}

func TestNewWithDefaultCleanupInterval(t *testing.T) {
	c := New[string]()

	expected := 5 * time.Minute
	if c.cleanupInterval != expected {
		t.Errorf("expected default cleanup interval %v, got %v", expected, c.cleanupInterval)
	}
}

func TestNewWithMultipleOptions(t *testing.T) {
	interval := 2 * time.Minute
	c := New(WithCleanupInterval[string](interval))

	if c.cleanupInterval != interval {
		t.Errorf("expected cleanup interval %v, got %v", interval, c.cleanupInterval)
	}
	if c.entries == nil {
		t.Error("expected entries map to be initialized")
	}
}

func TestCleanup(t *testing.T) {
	c := New(WithCleanupInterval[time.Time](100 * time.Millisecond))

	now := time.Now()
	pastTime := now.Add(-time.Hour)
	futureTime := now.Add(time.Hour)

	c.Set("expired1", pastTime)
	c.Set("expired2", pastTime)
	c.Set("valid1", futureTime)
	c.Set("valid2", futureTime)

	if c.Size() != 4 {
		t.Errorf("expected 4 entries before cleanup, got %d", c.Size())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go c.Cleanup(ctx, func(key string, expiry time.Time) bool {
		return expiry.Before(now)
	})

	time.Sleep(200 * time.Millisecond)

	if c.Size() != 2 {
		t.Errorf("expected 2 entries after cleanup, got %d", c.Size())
	}

	keys := c.Keys()
	sort.Strings(keys)
	expected := []string{"valid1", "valid2"}
	if !reflect.DeepEqual(keys, expected) {
		t.Errorf("expected keys %v after cleanup, got %v", expected, keys)
	}
}

func TestCleanupContextCancellation(t *testing.T) {
	c := New(WithCleanupInterval[string](50 * time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())

	cleanupDone := make(chan bool)
	go func() {
		c.Cleanup(ctx, func(key string, value string) bool {
			return false
		})
		cleanupDone <- true
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-cleanupDone:
	case <-time.After(200 * time.Millisecond):
		t.Error("cleanup should have stopped after context cancellation")
	}
}
