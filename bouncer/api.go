package bouncer

import (
	"context"
)

type Bouncer interface {
	Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error)
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

func ptr[T any](v T) *T {
	return &v
}
