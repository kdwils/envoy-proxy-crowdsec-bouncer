package bouncer

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEnvoyBouncer_Bounce(t *testing.T) {
	t.Run("empty ip", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		banned, err := b.Bounce(context.TODO(), "", nil)
		assert.Error(t, err)
		assert.Equal(t, "no ip found", err.Error())
		assert.False(t, banned)
		assert.Equal(t, int64(0), atomic.LoadInt64(&b.metrics.TotalRequests))
		assert.Equal(t, 0, len(b.metrics.HitsByIP))
	})

	t.Run("header too big", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		headers := map[string]string{
			"x-forwarded-for": strings.Repeat("a", maxHeaderLength+1),
		}
		banned, err := b.Bounce(context.TODO(), "192.168.1.1", headers)
		assert.Error(t, err)
		assert.Equal(t, "header too big", err.Error())
		assert.False(t, banned)
		assert.Equal(t, 0, len(b.metrics.HitsByIP))
	})

	t.Run("too many ips in chain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		ips := make([]string, maxIPs+1)
		for i := range ips {
			ips[i] = "192.168.1.1"
		}
		headers := map[string]string{
			"x-forwarded-for": strings.Join(ips, ","),
		}
		banned, err := b.Bounce(context.TODO(), "192.168.1.1", headers)
		assert.Error(t, err)
		assert.Equal(t, "too many ips in chain", err.Error())
		assert.False(t, banned)
		assert.Equal(t, 0, len(b.metrics.HitsByIP))
	})

	t.Run("invalid ip", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		banned, err := b.Bounce(context.TODO(), "not-an-ip", nil)
		assert.Error(t, err)
		assert.Equal(t, "invalid ip address", err.Error())
		assert.False(t, banned)
		assert.Equal(t, 0, len(b.metrics.HitsByIP))
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, errors.New("bouncer error"))
		banned, err := b.Bounce(context.TODO(), "192.168.1.1", nil)
		assert.Error(t, err)
		assert.Equal(t, "bouncer error", err.Error())
		assert.False(t, banned)
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("no decisions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, nil)
		banned, err := b.Bounce(context.TODO(), "192.168.1.1", nil)
		assert.NoError(t, err)
		assert.False(t, banned)

		entry, ok := cache.Get("192.168.1.1")
		assert.True(t, ok)
		assert.False(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("ip banned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		ip := "192.168.1.1"
		decisionType := "ban"
		decisions := &models.GetDecisionsResponse{
			{
				Value: &ip,
				Type:  &decisionType,
			},
		}
		mockBouncer.EXPECT().Get(ip).Return(decisions, nil)
		banned, err := b.Bounce(context.TODO(), ip, nil)
		assert.NoError(t, err)
		assert.True(t, banned)

		entry, ok := cache.Get(ip)
		assert.True(t, ok)
		assert.True(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, int64(1), atomic.LoadInt64(&b.metrics.TotalRequests))
		assert.Equal(t, int64(1), atomic.LoadInt64(&b.metrics.BouncedRequests))
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("ip not banned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer, cache: cache, metrics: &Metrics{}}
		ip := "192.168.1.1"
		decisionType := "allow"
		decisions := &models.GetDecisionsResponse{
			{
				Value: &ip,
				Type:  &decisionType,
			},
		}
		mockBouncer.EXPECT().Get(ip).Return(decisions, nil)
		banned, err := b.Bounce(context.TODO(), ip, nil)
		assert.NoError(t, err)
		assert.False(t, banned)

		entry, ok := cache.Get(ip)
		assert.True(t, ok)
		assert.False(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("trusted proxy chain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cache := cache.New(time.Minute, 10)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{
			bouncer: mockBouncer,
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("10.0.0.1"),
					Mask: net.CIDRMask(32, 32),
				},
			},
			cache:   cache,
			metrics: &Metrics{},
		}
		headers := map[string]string{
			"x-forwarded-for": "192.168.1.1,10.0.0.1",
		}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, nil)
		banned, err := b.Bounce(context.TODO(), "192.168.1.1", headers)
		assert.NoError(t, err)
		assert.False(t, banned)

		entry, ok := cache.Get("192.168.1.1")
		assert.True(t, ok)
		assert.False(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("ip already cached - bounced", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cache := cache.New(time.Minute, 10)
		cache.Set("192.168.1.1", true)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{
			bouncer: mockBouncer,
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("10.0.0.1"),
					Mask: net.CIDRMask(32, 32),
				},
			},
			cache:   cache,
			metrics: &Metrics{},
		}
		headers := map[string]string{
			"x-forwarded-for": "192.168.1.1,10.0.0.1",
		}

		bounced, err := b.Bounce(context.TODO(), "192.168.1.1", headers)
		assert.NoError(t, err)
		assert.True(t, bounced)

		entry, ok := cache.Get("192.168.1.1")
		assert.True(t, ok)
		assert.True(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, int64(1), atomic.LoadInt64(&b.metrics.TotalRequests))
		assert.Equal(t, int64(1), atomic.LoadInt64(&b.metrics.BouncedRequests))
		assert.Equal(t, int64(1), atomic.LoadInt64(&b.metrics.CachedRequests))
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("ip already cached - ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cache := cache.New(time.Minute, 10)
		cache.Set("192.168.1.1", false)

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{
			bouncer: mockBouncer,
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("10.0.0.1"),
					Mask: net.CIDRMask(32, 32),
				},
			},
			cache:   cache,
			metrics: &Metrics{},
		}
		headers := map[string]string{
			"x-forwarded-for": "192.168.1.1,10.0.0.1",
		}

		banned, err := b.Bounce(context.TODO(), "192.168.1.1", headers)
		assert.NoError(t, err)
		assert.False(t, banned)

		entry, ok := cache.Get("192.168.1.1")
		assert.True(t, ok)
		assert.False(t, entry.Bounced)
		assert.False(t, entry.Expired())
		assert.Equal(t, 1, len(b.metrics.HitsByIP))
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})
}

func TestEnvoyBouncer_isTrustedProxy(t *testing.T) {
	t.Run("invalid ip", func(t *testing.T) {
		b := &EnvoyBouncer{}
		result := b.isTrustedProxy("not-an-ip")
		assert.False(t, result)
	})

	t.Run("ip in trusted range", func(t *testing.T) {
		b := &EnvoyBouncer{
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
		}
		result := b.isTrustedProxy("192.168.1.100")
		assert.True(t, result)

	})

	t.Run("ip not in trusted range", func(t *testing.T) {
		b := &EnvoyBouncer{
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
			},
		}
		result := b.isTrustedProxy("192.168.2.1")
		assert.False(t, result)
	})

	t.Run("multiple trusted ranges", func(t *testing.T) {
		b := &EnvoyBouncer{
			trustedProxies: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.CIDRMask(24, 32),
				},
				{
					IP:   net.ParseIP("10.0.0.0"),
					Mask: net.CIDRMask(8, 32),
				},
			},
		}
		result := b.isTrustedProxy("10.1.1.1")
		assert.True(t, result)
	})
}

func TestParseProxyAddresses(t *testing.T) {
	t.Run("valid IPv4", func(t *testing.T) {
		proxies := []string{"192.168.1.1"}
		result, err := parseProxyAddresses(proxies)
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "192.168.1.1/32", result[0].String())
	})

	t.Run("valid IPv6", func(t *testing.T) {
		proxies := []string{"2001:db8::1"}
		result, err := parseProxyAddresses(proxies)
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "2001:db8::1/128", result[0].String())
	})

	t.Run("valid CIDR", func(t *testing.T) {
		proxies := []string{"192.168.1.0/24", "2001:db8::/64"}
		result, err := parseProxyAddresses(proxies)
		assert.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "192.168.1.0/24", result[0].String())
		assert.Equal(t, "2001:db8::/64", result[1].String())
	})

	t.Run("invalid address", func(t *testing.T) {
		proxies := []string{"invalid"}
		result, err := parseProxyAddresses(proxies)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid proxy address")
	})

	t.Run("empty list", func(t *testing.T) {
		proxies := []string{}
		result, err := parseProxyAddresses(proxies)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}
func TestEnvoyBouncer_metricsUpdater(t *testing.T) {
	t.Run("metrics update", func(t *testing.T) {
		cache := cache.New(time.Minute, 10)
		b := &EnvoyBouncer{
			cache:   cache,
			metrics: &Metrics{},
		}

		atomic.StoreInt64(&b.metrics.TotalRequests, 100)
		atomic.StoreInt64(&b.metrics.BouncedRequests, 25)
		atomic.StoreInt64(&b.metrics.CachedRequests, 75)
		cache.Set("1.1.1.1", true)

		metrics := &models.RemediationComponentsMetrics{}
		updateInterval := 10 * time.Second

		b.metricsUpdater(metrics, updateInterval)

		assert.Len(t, metrics.Metrics, 1)
		assert.Len(t, metrics.Metrics[0].Items, 4)

		assert.NotNil(t, metrics.Metrics[0].Meta.UtcNowTimestamp)
		assert.Equal(t, int64(10), *metrics.Metrics[0].Meta.WindowSizeSeconds)

		for _, item := range metrics.Metrics[0].Items {
			switch *item.Name {
			case "processed":
				assert.Equal(t, float64(100), *item.Value)
				assert.Equal(t, "requests", *item.Unit)
			case "bounced":
				assert.Equal(t, float64(25), *item.Value)
				assert.Equal(t, "requests", *item.Unit)
			case "cached":
				assert.Equal(t, float64(75), *item.Value)
				assert.Equal(t, "requests", *item.Unit)
			case "count":
				assert.Equal(t, float64(1), *item.Value)
				assert.Equal(t, "ips", *item.Unit)
			}
		}
	})
}
func TestEnvoyBouncer_IncHitsByIP(t *testing.T) {
	t.Run("first hit", func(t *testing.T) {
		b := &EnvoyBouncer{
			metrics: &Metrics{},
			mu:      sync.RWMutex{},
		}

		b.IncHitsByIP("192.168.1.1")

		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("multiple hits", func(t *testing.T) {
		b := &EnvoyBouncer{
			metrics: &Metrics{
				HitsByIP: map[string]int64{
					"192.168.1.1": 1,
				},
			},
			mu: sync.RWMutex{},
		}

		b.IncHitsByIP("192.168.1.1")
		b.IncHitsByIP("192.168.1.1")

		assert.Equal(t, int64(3), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("multiple IPs", func(t *testing.T) {
		b := &EnvoyBouncer{
			metrics: &Metrics{},
			mu:      sync.RWMutex{},
		}

		b.IncHitsByIP("192.168.1.1")
		b.IncHitsByIP("192.168.1.2")

		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.2"])
	})
}
