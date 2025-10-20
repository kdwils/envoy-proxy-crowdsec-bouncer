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

func TestNewWithNoCleanupInterval(t *testing.T) {
	c := New[string]()

	expected := time.Duration(0)
	if c.cleanupInterval != expected {
		t.Errorf("expected no cleanup interval %v, got %v", expected, c.cleanupInterval)
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

func TestWithCleanup(t *testing.T) {
	interval := 10 * time.Minute
	cleanupFunc := func(key string, value time.Time) bool {
		return time.Now().After(value)
	}

	c := New(WithCleanup[time.Time](interval, cleanupFunc))

	if c.cleanupInterval != interval {
		t.Errorf("expected cleanup interval %v, got %v", interval, c.cleanupInterval)
	}

	if c.cleanupFunc == nil {
		t.Error("expected cleanup func to be set")
	}
}

func TestStartCleanup(t *testing.T) {
	now := time.Now()
	pastTime := now.Add(-time.Hour)
	futureTime := now.Add(time.Hour)

	c := New(WithCleanup[time.Time](100*time.Millisecond, func(key string, expiry time.Time) bool {
		return expiry.Before(now)
	}))

	c.Set("expired1", pastTime)
	c.Set("expired2", pastTime)
	c.Set("valid1", futureTime)
	c.Set("valid2", futureTime)

	if c.Size() != 4 {
		t.Errorf("expected 4 entries before cleanup, got %d", c.Size())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

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

	val1, ok1 := c.Get("valid1")
	val2, ok2 := c.Get("valid2")
	if !ok1 || !ok2 {
		t.Error("expected valid entries to remain in cache")
	}
	if !val1.Equal(futureTime) || !val2.Equal(futureTime) {
		t.Error("expected valid entries to have correct values")
	}

	_, expired1Exists := c.Get("expired1")
	_, expired2Exists := c.Get("expired2")
	if expired1Exists || expired2Exists {
		t.Error("expected expired entries to be removed from cache")
	}
}

func TestStartCleanupWithNoCleanupFunc(t *testing.T) {
	c := New(WithCleanupInterval[string](100 * time.Millisecond))

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

	time.Sleep(150 * time.Millisecond)

	if c.Size() != 2 {
		t.Errorf("expected no cleanup without cleanup func, got size %d", c.Size())
	}

	val1, ok1 := c.Get("key1")
	val2, ok2 := c.Get("key2")
	if !ok1 || !ok2 {
		t.Error("expected all entries to remain without cleanup func")
	}
	if val1 != "value1" || val2 != "value2" {
		t.Error("expected entries to have correct values")
	}
}

func TestStartCleanupContextCancellation(t *testing.T) {
	deletionCount := 0
	c := New(WithCleanup[string](50*time.Millisecond, func(key string, value string) bool {
		deletionCount++
		return false
	}))

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	ctx, cancel := context.WithCancel(context.Background())

	c.StartCleanup(ctx)

	time.Sleep(100 * time.Millisecond)
	initialDeletionCount := deletionCount

	cancel()

	time.Sleep(150 * time.Millisecond)

	if deletionCount > initialDeletionCount+2 {
		t.Error("cleanup should have stopped after context cancellation")
	}

	if c.Size() != 2 {
		t.Errorf("expected 2 entries after cancellation, got %d", c.Size())
	}

	val1, ok1 := c.Get("key1")
	val2, ok2 := c.Get("key2")
	if !ok1 || !ok2 {
		t.Error("expected all entries to remain")
	}
	if val1 != "value1" || val2 != "value2" {
		t.Error("expected entries to have correct values")
	}
}
