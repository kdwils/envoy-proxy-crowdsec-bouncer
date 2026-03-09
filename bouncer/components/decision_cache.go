package components

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/version"
)

type DecisionCache struct {
	stream         *csbouncer.StreamBouncer
	decisions      *cache.Cache[models.Decision]
	mu             *sync.RWMutex
	MetricsService *crowdsec.MetricsService
	syncComplete   bool
}

func validateAuth(cfg config.Bouncer) error {
	if cfg.ApiKey != "" && cfg.TLS.Enabled {
		return errors.New("cannot use both API key and certificate auth")
	}
	if cfg.ApiKey == "" && !cfg.TLS.Enabled {
		return errors.New("api key or certificate (cert and key paths) required")
	}
	if cfg.TLS.Enabled && (cfg.TLS.CertPath == "" || cfg.TLS.KeyPath == "") {
		return errors.New("certificate auth requires both certPath and keyPath")
	}
	return nil
}

func NewDecisionCache(cfg config.Bouncer, MetricsService *crowdsec.MetricsService) (*DecisionCache, error) {
	if err := validateAuth(cfg); err != nil {
		return nil, err
	}

	stream, err := newStreamBouncer(cfg)
	if err != nil {
		return nil, err
	}
	dc := &DecisionCache{
		stream:         stream,
		decisions:      cache.New[models.Decision](),
		mu:             new(sync.RWMutex),
		MetricsService: MetricsService,
	}

	return dc, nil
}

func newStreamBouncer(cfg config.Bouncer) (*csbouncer.StreamBouncer, error) {
	b := &csbouncer.StreamBouncer{
		APIKey:         cfg.ApiKey,
		APIUrl:         cfg.LAPIURL,
		UserAgent:      "envoy-proxy-bouncer/" + version.Version,
		TickerInterval: cfg.TickerInterval,
		CertPath:       cfg.TLS.CertPath,
		KeyPath:        cfg.TLS.KeyPath,
		CAPath:         cfg.TLS.CAPath,
	}
	if cfg.TLS.InsecureSkipVerify {
		v := cfg.TLS.InsecureSkipVerify
		b.InsecureSkipVerify = &v
	}
	b.RetryInitialConnect = true

	err := b.Init()
	return b, err
}

func NewLiveBouncer(cfg config.Bouncer) (*csbouncer.LiveBouncer, error) {
	if err := validateAuth(cfg); err != nil {
		return nil, err
	}

	b := &csbouncer.LiveBouncer{
		APIKey:    cfg.ApiKey,
		APIUrl:    cfg.LAPIURL,
		UserAgent: "envoy-proxy-bouncer/" + version.Version,
		CertPath:  cfg.TLS.CertPath,
		KeyPath:   cfg.TLS.KeyPath,
		CAPath:    cfg.TLS.CAPath,
	}
	if cfg.TLS.InsecureSkipVerify {
		v := cfg.TLS.InsecureSkipVerify
		b.InsecureSkipVerify = &v
	}

	err := b.Init()
	return b, err
}

func (dc *DecisionCache) GetDecision(ctx context.Context, ip string) (*models.Decision, error) {
	logger := logger.FromContext(ctx).With(slog.String("method", "get_decision"))
	if ip == "" {
		logger.Debug("no ip provided")
		return nil, errors.New("no ip found")
	}

	if dc.decisions == nil {
		logger.Debug("cache is nil")
		return nil, errors.New("cache is nil")
	}

	logger = logger.With(slog.String("ip", ip))
	logger.Debug("checking for decision")

	decision, ok := dc.decisions.Get(ip)
	if !ok {
		logger.Debug("not found in cache")
		return nil, nil
	}

	logger.Debug("decision found", "type", *decision.Type)
	return &decision, nil
}

func (dc *DecisionCache) Size() int {
	if dc.decisions == nil {
		return 0
	}
	return dc.decisions.Size()
}

func (dc *DecisionCache) IsReady() bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return dc.syncComplete
}

func (dc *DecisionCache) GetOriginCounts() map[string]int {
	originCounts := make(map[string]int)
	if dc.decisions == nil {
		return originCounts
	}

	for _, key := range dc.decisions.Keys() {
		decision, exists := dc.decisions.Get(key)
		if exists && decision.Origin != nil {
			originCounts[*decision.Origin]++
		}
	}

	return originCounts
}

func (dc *DecisionCache) Sync(ctx context.Context) error {
	if dc.stream == nil {
		return errors.New("stream not initialized")
	}

	logger := logger.FromContext(ctx).With(slog.String("component", "bouncer"), slog.String("method", "sync"))
	go func() {
		dc.stream.Run(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("sync context done")
			return nil
		case d, ok := <-dc.stream.Stream:
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
				dc.decisions.Delete(*decision.Value)

				if dc.MetricsService == nil || decision.Origin == nil {
					continue
				}

				origin := *decision.Origin
				key := "active_decisions:" + origin
				dc.MetricsService.Dec(key, "active_decisions", "ip", map[string]string{
					"origin": origin,
				})

			}

			for _, decision := range d.New {
				if decision == nil || decision.Value == nil {
					continue
				}
				logger.Debug("received new decision", "decision", decision)
				dc.decisions.Set(*decision.Value, *decision)

				if dc.MetricsService == nil || decision.Origin == nil {
					continue
				}

				origin := *decision.Origin
				key := "active_decisions:" + origin
				dc.MetricsService.Inc(key, "active_decisions", "ip", map[string]string{
					"origin": origin,
				})
			}

			dc.mu.Lock()
			if !dc.syncComplete {
				dc.syncComplete = true
				logger.Info("initial decision sync complete")
			}
			dc.mu.Unlock()
		}
	}
}
