package cache

import (
	"context"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheLifecycle(t *testing.T) {
	c := New[string, models.Decision]()

	ip := "192.168.1.1"
	decision := models.Decision{
		ID:       1,
		Origin:   new("test"),
		Type:     new("ban"),
		Value:    &ip,
		Duration: new(time.Hour.String()),
		Scenario: new("test"),
	}

	assert.Equal(t, 0, c.Size())

	c.Set(ip, decision)
	assert.Equal(t, 1, c.Size())

	got, ok := c.Get(ip)
	require.True(t, ok)
	assert.Equal(t, decision, got)

	c.Delete(ip)
	assert.Equal(t, 0, c.Size())

	_, ok = c.Get(ip)
	assert.False(t, ok)
}

func TestCacheKeys(t *testing.T) {
	c := New[string, string]()
	assert.Empty(t, c.Keys())

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"key1", "key2", "key3"}, keys)

	c.Delete("key2")
	keys = c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"key1", "key3"}, keys)
}

func TestNew(t *testing.T) {
	cleanupFunc := func(key, value string) bool { return false }

	tests := []struct {
		name        string
		opts        []Option[string, string]
		want        time.Duration
		wantCleanup bool
	}{
		{name: "default", want: 0, wantCleanup: false},
		{
			name: "with cleanup interval",
			opts: []Option[string, string]{WithCleanupInterval[string, string](10 * time.Minute)},
			want: 10 * time.Minute,
		},
		{
			name:        "with cleanup",
			opts:        []Option[string, string]{WithCleanup[string, string](10*time.Minute, cleanupFunc)},
			want:        10 * time.Minute,
			wantCleanup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.opts...)

			assert.Equal(t, tt.want, c.cleanupInterval)
			if tt.wantCleanup {
				assert.NotNil(t, c.cleanupFunc)
				return
			}
			assert.Nil(t, c.cleanupFunc)
		})
	}
}

func TestCleanup(t *testing.T) {
	c := New(WithCleanupInterval[string, time.Time](100 * time.Millisecond))

	now := time.Now()
	pastTime := now.Add(-time.Hour)
	futureTime := now.Add(time.Hour)

	c.Set("expired1", pastTime)
	c.Set("expired2", pastTime)
	c.Set("valid1", futureTime)
	c.Set("valid2", futureTime)

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	go c.Cleanup(ctx, func(key string, expiry time.Time) bool {
		return expiry.Before(now)
	})

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 2, c.Size())

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"valid1", "valid2"}, keys)
}

func TestCleanupContextCancellation(t *testing.T) {
	c := New(WithCleanupInterval[string, string](50 * time.Millisecond))

	ctx, cancel := context.WithCancel(t.Context())

	cleanupDone := make(chan struct{})
	go func() {
		c.Cleanup(ctx, func(key, value string) bool { return false })
		close(cleanupDone)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	done := false
	select {
	case <-cleanupDone:
		done = true
	case <-time.After(200 * time.Millisecond):
	}
	assert.True(t, done, "cleanup should have stopped after context cancellation")
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

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 2, c.Size())

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"valid1", "valid2"}, keys)
}

func TestStartCleanupWithNoCleanupFunc(t *testing.T) {
	c := New(WithCleanupInterval[string, string](100 * time.Millisecond))
	c.Set("key1", "value1")
	c.Set("key2", "value2")

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	c.StartCleanup(ctx)

	time.Sleep(150 * time.Millisecond)

	assert.Equal(t, 2, c.Size())

	keys := c.Keys()
	sort.Strings(keys)
	assert.Equal(t, []string{"key1", "key2"}, keys)
}

func TestStartCleanupContextCancellation(t *testing.T) {
	var deletionCount atomic.Int32
	c := New(WithCleanup(50*time.Millisecond, func(key, value string) bool {
		deletionCount.Add(1)
		return false
	}))
	c.Set("key1", "value1")
	c.Set("key2", "value2")

	ctx, cancel := context.WithCancel(t.Context())

	c.StartCleanup(ctx)

	time.Sleep(100 * time.Millisecond)
	initialDeletionCount := deletionCount.Load()

	cancel()

	time.Sleep(150 * time.Millisecond)

	assert.LessOrEqual(t, deletionCount.Load(), initialDeletionCount+2)
	assert.Equal(t, 2, c.Size())
}
