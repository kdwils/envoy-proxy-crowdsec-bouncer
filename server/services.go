package server

import (
	"context"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/remediation"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/components"
)

//go:generate mockgen -destination=mocks/mock_remediator.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/server Remediator
type Remediator interface {
	Check(ctx context.Context, req *auth.CheckRequest) remediation.CheckedRequest
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

//go:generate mockgen -destination=mocks/mock_captcha.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/server Captcha
type Captcha interface {
	GetProviderName() string
	GetSession(sessionID string) (*components.CaptchaSession, bool)
	VerifyResponse(ctx context.Context, req components.VerificationRequest) (*components.VerificationResult, error)
	DeleteSession(sessionID string)
	StartCleanup(ctx context.Context)
}
