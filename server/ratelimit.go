package server

import (
	"context"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"golang.org/x/time/rate"
)

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

type RateLimiter struct {
	limiters *cache.Cache[string, rateLimiterEntry]
	rate     rate.Limit
	burst    int
	ttl      time.Duration
}

func NewRateLimiter(requestsPerSecond float64, burst int, ttl, cleanupInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rate:  rate.Limit(requestsPerSecond),
		burst: burst,
		ttl:   ttl,
	}
	rl.limiters = cache.New(
		cache.WithCleanup(cleanupInterval, func(key string, value rateLimiterEntry) bool {
			return time.Since(value.lastUsed) > rl.ttl
		}),
	)
	return rl
}

func (rl *RateLimiter) Start(ctx context.Context) {
	rl.limiters.StartCleanup(ctx)
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	entry, exists := rl.limiters.Get(ip)
	if !exists {
		entry = rateLimiterEntry{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastUsed: time.Now(),
		}
		rl.limiters.Set(ip, entry)
		return entry.limiter
	}

	entry.lastUsed = time.Now()
	rl.limiters.Set(ip, entry)
	return entry.limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}
