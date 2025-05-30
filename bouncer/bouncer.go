package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/version"
	"github.com/sirupsen/logrus"
)

const (
	maxHeaderLength = 1024
	maxIPs          = 20
)

type Metrics struct {
	TotalRequests     int64 `json:"total_requests"`
	BannedRequests    int64 `json:"banned_requests"`
	CacheHits         int64 `json:"cache_hits"`
	CacheMisses       int64 `json:"cache_misses"`
	StreamedDecisions int64 `json:"streamed_decisions"`
}

type EnvoyBouncer struct {
	stream          *csbouncer.StreamBouncer
	bouncer         LiveBouncerClient
	trustedProxies  []*net.IPNet
	cache           *cache.Cache
	metrics         *Metrics
	metricsProvider *csbouncer.MetricsProvider
}

func NewEnvoyBouncer(apiKey, apiURL string, trustedProxies []string, cache *cache.Cache) (Bouncer, error) {
	stream, err := newStreamBouncer(apiKey, apiURL)
	if err != nil {
		return nil, err
	}

	addresses, err := parseProxyAddresses(trustedProxies)
	if err != nil {
		return nil, err
	}

	bouncer, err := newLiveBouncer(apiKey, apiURL)
	if err != nil {
		return nil, err
	}

	b := &EnvoyBouncer{
		bouncer:        bouncer,
		stream:         stream,
		trustedProxies: addresses,
		cache:          cache,
		metrics:        &Metrics{},
	}

	provider, err := csbouncer.NewMetricsProvider(bouncer.APIClient, bouncer.UserAgent, b.metricsUpdater, logrus.StandardLogger())
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics provider: %w", err)
	}

	b.metricsProvider = provider

	return b, nil
}

func parseProxyAddresses(trustedProxies []string) ([]*net.IPNet, error) {
	ipNets := make([]*net.IPNet, 0, len(trustedProxies))
	for _, proxy := range trustedProxies {
		if !strings.Contains(proxy, "/") {
			if strings.Contains(proxy, ":") {
				proxy = proxy + "/128" // IPv6
			} else {
				proxy = proxy + "/32" // IPv4
			}
		}

		_, ipNet, err := net.ParseCIDR(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy address %s: %v", proxy, err)
		}
		ipNets = append(ipNets, ipNet)
	}

	return ipNets, nil
}

func newStreamBouncer(apiKey, apiURL string) (*csbouncer.StreamBouncer, error) {
	b := &csbouncer.StreamBouncer{
		APIKey:    apiKey,
		APIUrl:    apiURL,
		UserAgent: "envoy-proxy-bouncer/" + version.Version,
	}

	err := b.Init()
	return b, err
}

func newLiveBouncer(apiKey, apiURL string) (*csbouncer.LiveBouncer, error) {
	b := &csbouncer.LiveBouncer{
		APIKey:    apiKey,
		APIUrl:    apiURL,
		UserAgent: "envoy-proxy-bouncer/" + version.Version,
	}

	err := b.Init()
	return b, err
}

func (b *EnvoyBouncer) metricsUpdater(met *models.RemediationComponentsMetrics, updateInterval time.Duration) {
	metrics := &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr(time.Now().Unix()),
			WindowSizeSeconds: ptr(int64(updateInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	}

	metrics.Items = append(metrics.Items, &models.MetricsDetailItem{
		Name:  ptr("dropped"),
		Value: ptr(float64(atomic.LoadInt64(&b.metrics.BannedRequests))),
		Unit:  ptr("requests"),
	})
	metrics.Items = append(metrics.Items, &models.MetricsDetailItem{
		Name:  ptr("processed"),
		Value: ptr(float64(atomic.LoadInt64(&b.metrics.TotalRequests))),
		Unit:  ptr("requests"),
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

	var xff string
	for k, v := range headers {
		if strings.EqualFold(k, "x-forwarded-for") {
			xff = v
			break
		}
	}
	if xff != "" {
		logger.Debug("found xff header", "xff", xff)
		if len(xff) > maxHeaderLength {
			logger.Warn("xff header too big", "length", len(xff))
			return false, errors.New("header too big")
		}
		ips := strings.Split(xff, ",")
		if len(ips) > maxIPs {
			logger.Warn("too many ips in xff header", "length", len(ips))
			return false, errors.New("too many ips in chain")
		}

		for i := len(ips) - 1; i >= 0; i-- {
			parsedIP := strings.TrimSpace(ips[i])
			if !b.isTrustedProxy(parsedIP) && isValidIP(parsedIP) {
				logger.Info("using ip from xff header", "ip", parsedIP)
				ip = parsedIP
				break
			}
		}
	}

	logger = logger.With(slog.String("ip", ip))
	logger.Debug("starting decision check")

	entry, ok := b.cache.Get(ip)
	if ok {
		b.IncCacheHits()
		logger.Debug("cache hit", "entry", entry)
		return entry.Bounced, nil
	}
	b.IncCacheMisses()

	if !isValidIP(ip) {
		logger.Error("invalid ip address")
		return false, errors.New("invalid ip address")
	}

	decisions, err := b.getDecision(ip)
	if err != nil {
		logger.Error("error getting decisions", "error", err)
		return false, err
	}
	if decisions == nil {
		logger.Debug("no decisions found for ip")
		b.cache.Set(ip, false)
		return false, nil
	}

	for _, decision := range *decisions {
		if decision.Value == nil || decision.Type == nil {
			logger.Warn("decision has nil value or type", "decision", decision)
			continue
		}
		if isBannedDecision(decision) {
			logger.Info("bouncing")
			b.cache.Set(ip, true)
			b.IncBannedRequests()
			return true, nil
		}
	}

	b.cache.Set(ip, false)
	logger.Debug("no ban decisions found")
	return false, nil
}

func (b *EnvoyBouncer) Sync(ctx context.Context) error {
	if b.bouncer == nil {
		return errors.New("bouncer not initialized")
	}

	logger := logger.FromContext(ctx).With(slog.String("method", "sync"))
	go func() {
		b.stream.Run(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("sync context done")
			return nil
		case d := <-b.stream.Stream:
			if d == nil {
				logger.Debug("received nil decision stream")
				continue
			}

			b.IncStreamedDecisions()

			for _, decision := range d.Deleted {
				if decision == nil || decision.Value == nil {
					continue
				}

				b.cache.Delete(*decision.Value)
			}

			for _, decision := range d.New {
				if decision == nil || decision.Value == nil {
					continue
				}

				b.cache.Set(*decision.Value, isBannedDecision(decision))
			}
		}
	}
}

func (b *EnvoyBouncer) Metrics(ctx context.Context) error {
	if b.metricsProvider == nil {
		return errors.New("metrics provider not initialized")
	}
	go b.metricsProvider.Run(ctx)

	logger := logger.FromContext(ctx).With(slog.String("method", "metrics"))

	for {
		select {
		case <-ctx.Done():
			logger.Debug("sync context done")
			return nil
		}
	}
}

func (b *EnvoyBouncer) getDecision(ip string) (*models.GetDecisionsResponse, error) {
	if b.bouncer == nil {
		return nil, errors.New("bouncer not initialized")
	}

	return b.bouncer.Get(ip)
}

func (b *EnvoyBouncer) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, ipNet := range b.trustedProxies {
		if ipNet.Contains(parsed) {
			return true
		}
	}
	return false
}

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

func isBannedDecision(decision *models.Decision) bool {
	return decision != nil && decision.Type != nil && strings.EqualFold(*decision.Type, "ban")
}

func (b *EnvoyBouncer) IncTotalRequests()     { atomic.AddInt64(&b.metrics.TotalRequests, 1) }
func (b *EnvoyBouncer) IncBannedRequests()    { atomic.AddInt64(&b.metrics.BannedRequests, 1) }
func (b *EnvoyBouncer) IncCacheHits()         { atomic.AddInt64(&b.metrics.CacheHits, 1) }
func (b *EnvoyBouncer) IncCacheMisses()       { atomic.AddInt64(&b.metrics.CacheMisses, 1) }
func (b *EnvoyBouncer) IncStreamedDecisions() { atomic.AddInt64(&b.metrics.StreamedDecisions, 1) }

func (b *EnvoyBouncer) GetMetrics() any {
	return map[string]any{
		"route":            "envoy",
		"name":             "envoy-gateway-bouncer/" + version.Version,
		"denied_requests":  atomic.LoadInt64(&b.metrics.BannedRequests),
		"allowed_requests": atomic.LoadInt64(&b.metrics.TotalRequests) - atomic.LoadInt64(&b.metrics.BannedRequests),
		"stream_new":       atomic.LoadInt64(&b.metrics.StreamedDecisions),
	}
}
