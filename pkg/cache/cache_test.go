package cache

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr[T any](v T) *T {
	return &v
}

func TestDecisionCache(t *testing.T) {
	c := New[models.Decision]()
	assert.Equal(t, 0, c.Size(), "expected empty cache")

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
	assert.Equal(t, 1, c.Size(), "expected cache size 1 after Set")

	got, ok := c.Get(ip)
	require.True(t, ok, "expected to find entry for %s", ip)
	assert.Equal(t, ip, *got.Value, "expected correct IP value")

	c.Delete(ip)
	assert.Equal(t, 0, c.Size(), "expected empty cache after delete")

	_, ok = c.Get(ip)
	assert.False(t, ok, "expected no entry for %s after delete", ip)
}

func TestCaptchaCache(t *testing.T) {
	c := New[time.Time]()
	assert.Equal(t, 0, c.Size(), "expected empty cache")

	ip := "192.168.1.1"
	expiry := time.Now().Add(time.Hour)
	c.Set(ip, expiry)
	assert.Equal(t, 1, c.Size(), "expected cache size 1 after Set")

	got, ok := c.Get(ip)
	require.True(t, ok, "expected to find entry for %s", ip)
	assert.True(t, got.Equal(expiry), "expected correct expiry time")

	c.Delete(ip)
	assert.Equal(t, 0, c.Size(), "expected empty cache after delete")

	_, ok = c.Get(ip)
	assert.False(t, ok, "expected no entry for %s after delete", ip)
}

func TestCacheKeys(t *testing.T) {
	c := New[string]()
	assert.Empty(t, c.Keys(), "expected no keys in empty cache")

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	keys := c.Keys()
	assert.Len(t, keys, 3, "expected 3 keys")

	sort.Strings(keys)
	assert.Equal(t, []string{"key1", "key2", "key3"}, keys, "expected correct keys")

	c.Delete("key2")
	keys = c.Keys()
	assert.Len(t, keys, 2, "expected 2 keys after delete")

	sort.Strings(keys)
	assert.Equal(t, []string{"key1", "key3"}, keys, "expected correct keys after delete")
}

func TestWithCleanupInterval(t *testing.T) {
	interval := 10 * time.Minute
	c := New(WithCleanupInterval[string](interval))

	assert.Equal(t, interval, c.cleanupInterval, "expected cleanup interval to be set")
}

func TestNewWithNoCleanupInterval(t *testing.T) {
	c := New[string]()

	assert.Equal(t, time.Duration(0), c.cleanupInterval, "expected no cleanup interval by default")
}

func TestNewWithMultipleOptions(t *testing.T) {
	interval := 2 * time.Minute
	c := New(WithCleanupInterval[string](interval))

	assert.Equal(t, interval, c.cleanupInterval, "expected cleanup interval to be set")
	assert.NotNil(t, c.entries, "expected entries map to be initialized")
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

	assert.Equal(t, 4, c.Size(), "expected 4 entries before cleanup")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go c.Cleanup(ctx, func(key string, expiry time.Time) bool {
		return expiry.Before(now)
	})

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 2, c.Size(), "expected 2 entries after cleanup")

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"valid1", "valid2"}, keys, "expected only valid keys to remain")
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

	c := New(WithCleanup(interval, cleanupFunc))

	assert.Equal(t, interval, c.cleanupInterval, "expected cleanup interval to be set")
	assert.NotNil(t, c.cleanupFunc, "expected cleanup func to be set")
}

func TestStartCleanup(t *testing.T) {
	now := time.Now()
	pastTime := now.Add(-time.Hour)
	futureTime := now.Add(time.Hour)

	c := New(WithCleanup(100*time.Millisecond, func(key string, expiry time.Time) bool {
		return expiry.Before(now)
	}))

	c.Set("expired1", pastTime)
	c.Set("expired2", pastTime)
	c.Set("valid1", futureTime)
	c.Set("valid2", futureTime)

	assert.Equal(t, 4, c.Size(), "expected 4 entries before cleanup")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 2, c.Size(), "expected 2 entries after cleanup")

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"valid1", "valid2"}, keys, "expected only valid keys to remain")

	val1, ok1 := c.Get("valid1")
	assert.True(t, ok1, "expected valid1 to exist in cache")
	assert.True(t, val1.Equal(futureTime), "expected valid1 to have correct value")

	val2, ok2 := c.Get("valid2")
	assert.True(t, ok2, "expected valid2 to exist in cache")
	assert.True(t, val2.Equal(futureTime), "expected valid2 to have correct value")

	_, expired1Exists := c.Get("expired1")
	assert.False(t, expired1Exists, "expected expired1 to be removed from cache")

	_, expired2Exists := c.Get("expired2")
	assert.False(t, expired2Exists, "expected expired2 to be removed from cache")
}

func TestStartCleanupWithNoCleanupFunc(t *testing.T) {
	c := New(WithCleanupInterval[string](100 * time.Millisecond))

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

	time.Sleep(150 * time.Millisecond)

	assert.Equal(t, 2, c.Size(), "expected no cleanup without cleanup func")

	val1, ok1 := c.Get("key1")
	assert.True(t, ok1, "expected key1 to exist")
	assert.Equal(t, "value1", val1, "expected key1 to have correct value")

	val2, ok2 := c.Get("key2")
	assert.True(t, ok2, "expected key2 to exist")
	assert.Equal(t, "value2", val2, "expected key2 to have correct value")
}

func TestStartCleanupContextCancellation(t *testing.T) {
	deletionCount := 0
	c := New(WithCleanup(50*time.Millisecond, func(key string, value string) bool {
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

	assert.LessOrEqual(t, deletionCount, initialDeletionCount+2, "cleanup should have stopped after context cancellation")
	assert.Equal(t, 2, c.Size(), "expected 2 entries after cancellation")

	val1, ok1 := c.Get("key1")
	assert.True(t, ok1, "expected key1 to exist")
	assert.Equal(t, "value1", val1, "expected key1 to have correct value")

	val2, ok2 := c.Get("key2")
	assert.True(t, ok2, "expected key2 to exist")
	assert.Equal(t, "value2", val2, "expected key2 to have correct value")
}
