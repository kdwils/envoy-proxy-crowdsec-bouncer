package bouncer

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncerClient interface {
	Init() error
	Get(string) (*models.GetDecisionsResponse, error)
}

type Bouncer interface {
	Bounce(r *http.Request) (bool, error)
}

func ptr[A any](thing A) *A {
	return &thing
}
