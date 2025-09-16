package server

import (
	"context"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/remediation"
)

//go:generate mockgen -destination=mocks/mock_remediator.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/server Remediator
type Remediator interface {
	Check(ctx context.Context, req *auth.CheckRequest) remediation.CheckedRequest
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

type Captcha = remediation.CaptchaService
