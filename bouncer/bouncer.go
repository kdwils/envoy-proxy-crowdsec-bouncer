package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/version"
)

const (
	maxHeaderLength = 1024
	maxIPs          = 20
)

type EnvoyBouncer struct {
	stream         *csbouncer.StreamBouncer
	bouncer        LiveBouncerClient
	trustedProxies []*net.IPNet
	cache          *cache.Cache
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
	}

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

func (b *EnvoyBouncer) Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error) {
	logger := logger.FromContext(ctx).With(slog.String("method", "bounce")).With(slog.String("headers", fmt.Sprintf("%+v", headers)))
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
		logger.Debug("cache hit", "entry", entry)
		if entry.Bounced {
			logger.Info("bouncing")
			return true, nil
		}
	}

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
