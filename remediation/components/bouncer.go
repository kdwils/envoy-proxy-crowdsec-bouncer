package components

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/version"
	"github.com/sirupsen/logrus"
)

func ptr[T any](v T) *T {
	return &v
}

const (
	maxHeaderLength = 1024
	maxIPs          = 20
)

type Metrics struct {
	TotalRequests   int64 `json:"total_requests"`
	BouncedRequests int64 `json:"banned_requests"`
}

type EnvoyBouncer struct {
	stream          *csbouncer.StreamBouncer
	cache           *cache.Cache
	metrics         *Metrics
	metricsProvider *csbouncer.MetricsProvider
	mu              *sync.RWMutex
}

func NewBouncer(apiKey, apiURL, tickerInterval string) (*EnvoyBouncer, error) {
	stream, err := newStreamBouncer(apiKey, apiURL, tickerInterval)
	if err != nil {
		return nil, err
	}

	b := &EnvoyBouncer{
		stream:  stream,
		cache:   cache.New(),
		metrics: new(Metrics),
		mu:      new(sync.RWMutex),
	}

	provider, err := csbouncer.NewMetricsProvider(stream.APIClient, stream.UserAgent, b.metricsUpdater, logrus.StandardLogger())
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics provider: %w", err)
	}

	b.metricsProvider = provider

	return b, nil
}

func newStreamBouncer(apiKey, apiURL, tickerInterval string) (*csbouncer.StreamBouncer, error) {
	b := &csbouncer.StreamBouncer{
		APIKey:         apiKey,
		APIUrl:         apiURL,
		UserAgent:      "envoy-proxy-bouncer/" + version.Version,
		TickerInterval: tickerInterval,
	}
	// ensure we don't exit on transient startup issues
	b.RetryInitialConnect = true

	err := b.Init()
	return b, err
}

func NewLiveBouncer(apiKey, apiURL string) (*csbouncer.LiveBouncer, error) {
	b := &csbouncer.LiveBouncer{
		APIKey:    apiKey,
		APIUrl:    apiURL,
		UserAgent: "envoy-proxy-bouncer/" + version.Version,
	}

	err := b.Init()
	return b, err
}
func (b *EnvoyBouncer) metricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	totalRequests := atomic.SwapInt64(&b.metrics.TotalRequests, 0)
	bouncedRequests := atomic.SwapInt64(&b.metrics.BouncedRequests, 0)

	if totalRequests == 0 && bouncedRequests == 0 {
		return
	}

	metrics := &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr(time.Now().Unix()),
			WindowSizeSeconds: ptr(int64(updateInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	}

	metrics.Items = append(metrics.Items, &models.MetricsDetailItem{
		Name:  ptr("requests"),
		Value: ptr(float64(totalRequests)),
		Unit:  ptr("processed"),
	})
	metrics.Items = append(metrics.Items, &models.MetricsDetailItem{
		Name:  ptr("requests"),
		Value: ptr(float64(bouncedRequests)),
		Unit:  ptr("bounced"),
	})

	met.Metrics = append(met.Metrics, metrics)
}

func (b *EnvoyBouncer) Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error) {
	logger := logger.FromContext(ctx).With(slog.String("method", "bounce"))
	if ip == "" {
		logger.Debug("no ip provided")
		return false, errors.New("no ip found")
	}

	if b.cache == nil {
		logger.Debug("cache is nil")
		return false, errors.New("cache is nil")
	}

	b.IncTotalRequests()

	logger = logger.With(slog.String("ip", ip))
	logger.Debug("starting decision check")

	decision, ok := b.cache.Get(ip)
	if !ok {
		logger.Debug("not found in cache")
		return false, nil
	}
	if IsBannedDecision(&decision) {
		logger.Debug("bouncing")
		b.IncBouncedRequests()
		return true, nil
	}

	logger.Debug("no ban decisions found")
	return false, nil
}

func (b *EnvoyBouncer) Sync(ctx context.Context) error {
	if b.stream == nil {
		return errors.New("stream not initialized")
	}

	logger := logger.FromContext(ctx).With(slog.String("component", "bouncer"), slog.String("method", "sync"))
	go func() {
		b.stream.Run(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("sync context done")
			return nil
		case d, ok := <-b.stream.Stream:
			if !ok {
				logger.Warn("decision stream closed; stopping sync")
				return nil
			}
			if d == nil {
				continue
			}

			for _, decision := range d.Deleted {
				if decision == nil || decision.Value == nil {
					continue
				}
				logger.Debug("deleting decision", "decision", decision)
				b.cache.Delete(*decision.Value)
			}

			for _, decision := range d.New {
				if decision == nil || decision.Value == nil {
					continue
				}
				logger.Debug("received new decision", "decision", decision)
				b.cache.Set(*decision.Value, *decision)
			}
		}
	}
}

func (b *EnvoyBouncer) Metrics(ctx context.Context) error {
	if b.metricsProvider == nil {
		return errors.New("metrics provider not initialized")
	}
	go b.metricsProvider.Run(ctx)
	<-ctx.Done()
	return nil
}

func IsBannedDecision(decision *models.Decision) bool {
	if decision == nil || decision.Type == nil {
		return false
	}
	return strings.EqualFold(*decision.Type, "ban")
}

func (b *EnvoyBouncer) IncTotalRequests() {
	if b.metrics == nil {
		return
	}
	atomic.AddInt64(&b.metrics.TotalRequests, 1)
}

func (b *EnvoyBouncer) IncBouncedRequests() {
	if b.metrics == nil {
		return
	}
	atomic.AddInt64(&b.metrics.BouncedRequests, 1)
}
