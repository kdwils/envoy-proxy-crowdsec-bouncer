package bouncer

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/stretchr/testify/assert"
)

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
		cache := cache.New()
		b := &EnvoyBouncer{
			cache:   cache,
			metrics: &Metrics{},
			mu:      new(sync.RWMutex),
		}

		atomic.StoreInt64(&b.metrics.TotalRequests, 100)
		atomic.StoreInt64(&b.metrics.BouncedRequests, 25)
		atomic.StoreInt64(&b.metrics.CachedRequests, 75)
		decision := models.Decision{
			Value: ptr("192.168.1.100"),
			Type:  ptr("ban"),
		}
		cache.Set("192.168.1.100", decision)

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

		assert.Equal(t, int64(0), b.metrics.TotalRequests)
		assert.Equal(t, int64(0), b.metrics.BouncedRequests)
		assert.Equal(t, int64(0), b.metrics.CachedRequests)
		assert.Equal(t, 0, len(b.metrics.HitsByIP))
	})
}
func TestEnvoyBouncer_IncHitsByIP(t *testing.T) {
	t.Run("first hit", func(t *testing.T) {
		b := &EnvoyBouncer{
			metrics: &Metrics{},
			mu:      new(sync.RWMutex),
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
			mu: new(sync.RWMutex),
		}

		b.IncHitsByIP("192.168.1.1")
		b.IncHitsByIP("192.168.1.1")

		assert.Equal(t, int64(3), b.metrics.HitsByIP["192.168.1.1"])
	})

	t.Run("multiple IPs", func(t *testing.T) {
		b := &EnvoyBouncer{
			metrics: &Metrics{},
			mu:      new(sync.RWMutex),
		}

		b.IncHitsByIP("192.168.1.1")
		b.IncHitsByIP("192.168.1.2")

		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.1"])
		assert.Equal(t, int64(1), b.metrics.HitsByIP["192.168.1.2"])
	})
}

func TestEnvoyBouncer_Bounce(t *testing.T) {
	testCache := cache.New()
	decision := models.Decision{
		Value: ptr("192.168.1.100"),
		Type:  ptr("ban"),
	}
	testCache.Set("192.168.1.100", decision)

	type fields struct {
		stream         *csbouncer.StreamBouncer
		trustedProxies []*net.IPNet
		cache          *cache.Cache
		metrics        *Metrics
		mu             *sync.RWMutex
	}
	type args struct {
		ctx     context.Context
		ip      string
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "empty ip",
			fields: fields{
				cache:   testCache,
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "nil cache",
			fields: fields{
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.1",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "invalid ip",
			fields: fields{
				cache:   testCache,
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "invalid-ip",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "xff header too long",
			fields: fields{
				cache:   testCache,
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.1",
				headers: map[string]string{
					"x-forwarded-for": strings.Repeat("a", 1025),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "too many ips in xff",
			fields: fields{
				cache:   testCache,
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.1",
				headers: map[string]string{
					"x-forwarded-for": strings.Repeat("1.1.1.1,", 21),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "banned ip found in cache",
			fields: fields{
				cache:   testCache,
				metrics: &Metrics{},
				mu:      &sync.RWMutex{},
			},
			args: args{
				ctx: context.Background(),
				ip:  "192.168.1.100",
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &EnvoyBouncer{
				stream:         tt.fields.stream,
				trustedProxies: tt.fields.trustedProxies,
				cache:          tt.fields.cache,
				metrics:        tt.fields.metrics,
				mu:             tt.fields.mu,
			}
			got, err := b.Bounce(tt.args.ctx, tt.args.ip, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("EnvoyBouncer.Bounce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EnvoyBouncer.Bounce() = %v, want %v", got, tt.want)
			}
		})
	}
}
