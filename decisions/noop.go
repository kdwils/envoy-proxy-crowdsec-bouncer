package decisions

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// NoopCache is a DecisionCache that never holds any decisions, used when the
// bouncer component is disabled so callers don't need to nil-check it.
type NoopCache struct{}

func NewNoopCache() *NoopCache {
	return &NoopCache{}
}

func (n *NoopCache) GetDecision(ctx context.Context, ip string) (*models.Decision, error) {
	return nil, nil
}

func (n *NoopCache) Sync(ctx context.Context) error {
	return nil
}

func (n *NoopCache) Size() int {
	return 0
}

func (n *NoopCache) GetOriginCounts() map[string]int {
	return map[string]int{}
}

func (n *NoopCache) IsReady() bool {
	return true
}
