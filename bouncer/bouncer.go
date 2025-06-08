package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

const (
	maxHeaderLength = 1024
	maxIPs          = 20
)

type Metrics struct {
	TotalRequests   int64            `json:"total_requests"`
	BouncedRequests int64            `json:"banned_requests"`
	HitsByIP        map[string]int64 `json:"hits_by_ip"`
}
type EnvoyBouncer struct {
	stream          *csbouncer.StreamBouncer
	trustedProxies  []*net.IPNet
	cache           *cache.Cache
	metrics         *Metrics
	metricsProvider *csbouncer.MetricsProvider
	mu              *sync.RWMutex
}

func NewEnvoyBouncer(apiKey, apiURL string, trustedProxies []string) (Bouncer, error) {
	stream, err := newStreamBouncer(apiKey, apiURL)
	if err != nil {
		return nil, err
	}

	addresses, err := parseProxyAddresses(trustedProxies)
	if err != nil {
		return nil, err
	}

	b := &EnvoyBouncer{
		stream:         stream,
		trustedProxies: addresses,
		cache:          cache.New(),
		metrics:        new(Metrics),
		mu:             new(sync.RWMutex),
	}

	provider, err := csbouncer.NewMetricsProvider(stream.APIClient, stream.UserAgent, b.metricsUpdater, logrus.StandardLogger())
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

	b.mu.Lock()
	uniqueIPs := len(b.metrics.HitsByIP)
	b.metrics.HitsByIP = make(map[string]int64)
	b.mu.Unlock()

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
	metrics.Items = append(metrics.Items, &models.MetricsDetailItem{
		Name:  ptr("unique"),
		Value: ptr(float64(uniqueIPs)),
		Unit:  ptr("ips"),
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
				logger.Debug("using ip from xff header", "ip", parsedIP)
				ip = parsedIP
				break
			}
		}
	}

	if !isValidIP(ip) {
		logger.Error("invalid ip address")
		return false, errors.New("invalid ip address")
	}

	logger = logger.With(slog.String("ip", ip), slog.String("xff", xff))
	logger.Debug("starting decision check")

	b.IncHitsByIP(ip)

	decision, ok := b.cache.Get(ip)
	if !ok {
		logger.Debug("not found in cache", "ip", ip)
		logger.Info("ok")
	}
	if IsBannedDecision(&decision) {
		logger.Info("bouncing")
		b.IncBouncedRequests()
		return true, nil
	}

	logger.Debug("no ban decisions found")
	logger.Info("ok")
	return false, nil
}

func (b *EnvoyBouncer) Sync(ctx context.Context) error {
	if b.stream == nil {
		return errors.New("stream not initialized")
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

	logger := logger.FromContext(ctx).With(slog.String("method", "metrics"))

	for {
		select {
		case <-ctx.Done():
			logger.Debug("metrics context done")
			return nil
		}
	}
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

func (b *EnvoyBouncer) IncHitsByIP(ip string) {
	if b.metrics == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.metrics.HitsByIP == nil {
		b.metrics.HitsByIP = make(map[string]int64)
	}

	b.metrics.HitsByIP[ip]++
}
