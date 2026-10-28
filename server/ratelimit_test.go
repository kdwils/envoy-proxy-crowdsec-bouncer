package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateLimiter_Allow(t *testing.T) {
	t.Run("allows requests under the limit", func(t *testing.T) {
		rl := NewRateLimiter(10, 10)

		for range 10 {
			require.True(t, rl.Allow("192.168.1.1"))
		}
	})

	t.Run("blocks requests over the limit", func(t *testing.T) {
		rl := NewRateLimiter(2, 2)

		require.True(t, rl.Allow("192.168.1.1"))
		require.True(t, rl.Allow("192.168.1.1"))
		require.False(t, rl.Allow("192.168.1.1"))
	})

	t.Run("tracks different IPs separately", func(t *testing.T) {
		rl := NewRateLimiter(1, 1)

		require.True(t, rl.Allow("192.168.1.1"))
		require.True(t, rl.Allow("192.168.1.2"))

		require.False(t, rl.Allow("192.168.1.1"))
		require.False(t, rl.Allow("192.168.1.2"))
	})

	t.Run("refills tokens over time", func(t *testing.T) {
		rl := NewRateLimiter(10, 1)

		require.True(t, rl.Allow("192.168.1.1"))
		require.False(t, rl.Allow("192.168.1.1"))

		time.Sleep(150 * time.Millisecond)

		require.True(t, rl.Allow("192.168.1.1"))
	})

	t.Run("evicts stale entries", func(t *testing.T) {
		rl := NewRateLimiterWithTTL(10, 10, 100*time.Millisecond, 50*time.Millisecond)

		ctx, cancel := context.WithCancel(t.Context())
		rl.Start(ctx)
		defer cancel()

		rl.Allow("192.168.1.1")
		require.Equal(t, 1, rl.limiters.Size())

		time.Sleep(200 * time.Millisecond)
		require.Eventually(t, func() bool {
			return rl.limiters.Size() == 0
		}, 2*time.Second, 50*time.Millisecond)
	})
}
