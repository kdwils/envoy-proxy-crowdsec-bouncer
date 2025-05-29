package bouncer

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncerClient interface {
	Init() error
	Get(string) (*models.GetDecisionsResponse, error)
}

type Bouncer interface {
	Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error)
}
