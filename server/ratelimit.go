package server

import (
	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiters *cache.Cache[*rate.Limiter]
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: cache.New[*rate.Limiter](),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	limiter, exists := rl.limiters.Get(ip)
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters.Set(ip, limiter)
	}

	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}
