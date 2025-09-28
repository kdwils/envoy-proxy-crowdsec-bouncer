package components

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/version"
)

type DecisionCache struct {
	stream    *csbouncer.StreamBouncer
	decisions *cache.Cache[models.Decision]
	mu        *sync.RWMutex
}

func NewDecisionCache(apiKey, apiURL, tickerInterval string) (*DecisionCache, error) {
	stream, err := newStreamBouncer(apiKey, apiURL, tickerInterval)
	if err != nil {
		return nil, err
	}
	dc := &DecisionCache{
		stream:    stream,
		decisions: cache.New[models.Decision](),
		mu:        new(sync.RWMutex),
	}

	return dc, nil
}

func newStreamBouncer(apiKey, apiURL, tickerInterval string) (*csbouncer.StreamBouncer, error) {
	b := &csbouncer.StreamBouncer{
		APIKey:         apiKey,
		APIUrl:         apiURL,
		UserAgent:      "envoy-proxy-bouncer/" + version.Version,
		TickerInterval: tickerInterval,
	}
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
			}

			for _, decision := range d.New {
				if decision == nil || decision.Value == nil {
					continue
				}
				logger.Debug("received new decision", "decision", decision)
				dc.decisions.Set(*decision.Value, *decision)
			}
		}
	}
}
