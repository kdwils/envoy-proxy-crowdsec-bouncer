package components

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:fix inline
func ptr[T any](v T) *T {
	return new(v)
}

func TestDecisionCache_GetDecision(t *testing.T) {
	ctx := context.Background()

	t.Run("empty ip", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		got, err := dc.GetDecision(ctx, "")
		require.Error(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty cache returns nil", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.cidrs = dc.buildIndex(ctx)
		got, err := dc.GetDecision(ctx, "192.168.1.1")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("decision found in cache", func(t *testing.T) {
		testCache := cache.New[string, models.Decision]()
		decision := models.Decision{Value: new("192.168.1.100"), Type: new("ban")}
		testCache.Set("192.168.1.100", decision)

		dc := &DecisionCache{
			decisions: testCache,
			mu:        &sync.RWMutex{},
		}
		dc.cidrs = dc.buildIndex(ctx)
		got, err := dc.GetDecision(ctx, "192.168.1.100")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, decision, *got)
	})

	t.Run("decision not found in cache", func(t *testing.T) {
		testCache := cache.New[string, models.Decision]()
		testCache.Set("192.168.1.100", models.Decision{Value: new("192.168.1.100"), Type: new("ban")})

		dc := &DecisionCache{
			decisions: testCache,
			mu:        &sync.RWMutex{},
		}
		dc.cidrs = dc.buildIndex(ctx)
		got, err := dc.GetDecision(ctx, "192.168.1.99")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("exact ipv4 match", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		want := models.Decision{Value: new("192.168.1.100"), Type: new("ban")}
		dc.decisions.Set("192.168.1.100", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "192.168.1.100")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("exact ipv6 match", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		want := models.Decision{Value: new("2001:db8::1"), Type: new("captcha")}
		dc.decisions.Set("2001:db8::1", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "2001:db8::1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("ipv4 cidr match", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		want := models.Decision{Value: new("10.0.0.0/8"), Type: new("ban")}
		dc.decisions.Set("10.0.0.0/8", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "10.1.2.3")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("ipv6 cidr match", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		want := models.Decision{Value: new("2001:db8::/32"), Type: new("ban")}
		dc.decisions.Set("2001:db8::/32", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "2001:db8::abcd")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("no match", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.decisions.Set("10.0.0.0/8", models.Decision{Value: new("10.0.0.0/8"), Type: new("ban")})
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "172.16.0.1")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("exact ip overrides cidr", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.decisions.Set("10.0.0.0/8", models.Decision{Value: new("10.0.0.0/8"), Type: new("ban")})
		want := models.Decision{Value: new("10.0.0.50"), Type: new("captcha")}
		dc.decisions.Set("10.0.0.50", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "10.0.0.50")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("more specific cidr overrides broader", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.decisions.Set("10.0.0.0/8", models.Decision{Value: new("10.0.0.0/8"), Type: new("ban")})
		want := models.Decision{Value: new("10.1.0.0/16"), Type: new("captcha")}
		dc.decisions.Set("10.1.0.0/16", want)
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "10.1.5.5")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)
	})

	t.Run("invalid decision value is ignored", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		want := models.Decision{Value: new("1.2.3.4"), Type: new("ban")}
		dc.decisions.Set("1.2.3.4", want)
		dc.decisions.Set("bad-key", models.Decision{Value: new("not-an-ip"), Type: new("ban")})
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "1.2.3.4")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want, *got)

		got2, err := dc.GetDecision(ctx, "not-an-ip")
		require.NoError(t, err)
		assert.Nil(t, got2)
	})

	t.Run("invalid ip format returns nil", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.decisions.Set("1.2.3.4", models.Decision{Value: new("1.2.3.4"), Type: new("ban")})
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "not-an-ip")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("rebuild after delete removes entry", func(t *testing.T) {
		dc := &DecisionCache{
			decisions: cache.New[string, models.Decision](),
			mu:        &sync.RWMutex{},
		}
		dc.decisions.Set("192.168.1.100", models.Decision{Value: new("192.168.1.100"), Type: new("ban")})
		dc.cidrs = dc.buildIndex(ctx)
		dc.decisions.Delete("192.168.1.100")
		dc.cidrs = dc.buildIndex(ctx)

		got, err := dc.GetDecision(ctx, "192.168.1.100")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func makeDecisions(count int, cidrRatio float64) *DecisionCache {
	dc := &DecisionCache{
		decisions: cache.New[string, models.Decision](),
		mu:        &sync.RWMutex{},
	}

	cidrCount := int(float64(count) * cidrRatio)
	for i := 0; i < count-cidrCount; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		dec := models.Decision{Value: new(ip), Type: new("ban")}
		dc.decisions.Set(ip, dec)
	}

	for i := range cidrCount {
		cidr := fmt.Sprintf("172.%d.0.0/16", i%256)
		dec := models.Decision{Value: new(cidr), Type: new("ban")}
		dc.decisions.Set(cidr, dec)
	}

	dc.cidrs = dc.buildIndex(context.Background())
	return dc
}

func BenchmarkGetDecision_ExactIP_1k(b *testing.B) {
	dc := makeDecisions(1000, 0)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		dc.GetDecision(ctx, ip)
	}
}

func BenchmarkGetDecision_ExactIP_10k(b *testing.B) {
	dc := makeDecisions(10000, 0)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		dc.GetDecision(ctx, ip)
	}
}

func BenchmarkGetDecision_CIDR_1k(b *testing.B) {
	dc := makeDecisions(1000, 0.5)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("172.%d.5.5", i%256)
		dc.GetDecision(ctx, ip)
	}
}

func BenchmarkGetDecision_Mixed_10k(b *testing.B) {
	dc := makeDecisions(10000, 0.3)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		dc.GetDecision(ctx, ip)
	}
}
