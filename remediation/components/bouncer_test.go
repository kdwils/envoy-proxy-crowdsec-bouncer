package components

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/stretchr/testify/assert"
)

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
		decision := models.Decision{
			Value: ptr("192.168.1.100"),
			Type:  ptr("ban"),
		}
		cache.Set("192.168.1.100", decision)

		metrics := &models.RemediationComponentsMetrics{}
		updateInterval := 10 * time.Second

		b.metricsUpdater(metrics, updateInterval)

		assert.Len(t, metrics.Metrics, 1)
		assert.Len(t, metrics.Metrics[0].Items, 2)

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
			case "count":
				assert.Equal(t, float64(1), *item.Value)
				assert.Equal(t, "ips", *item.Unit)
			}
		}

		assert.Equal(t, int64(0), b.metrics.TotalRequests)
		assert.Equal(t, int64(0), b.metrics.BouncedRequests)
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
		stream  *csbouncer.StreamBouncer
		cache   *cache.Cache
		metrics *Metrics
		mu      *sync.RWMutex
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
				stream:  tt.fields.stream,
				cache:   tt.fields.cache,
				metrics: tt.fields.metrics,
				mu:      tt.fields.mu,
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
