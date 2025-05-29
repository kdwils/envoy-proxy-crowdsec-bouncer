package bouncer

import (
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncerClient interface {
	Init() error
	Get(string) (*models.GetDecisionsResponse, error)
}

type Bouncer interface {
	Bounce(ip string, headers map[string]string) (bool, error)
}

func ptr[A any](thing A) *A {
	return &thing
}
