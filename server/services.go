package server

import (
	"context"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/template"
)

//go:generate mockgen -destination=mocks/mock_bouncer.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/server Bouncer
type Bouncer interface {
	Check(ctx context.Context, req *auth.CheckRequest) bouncer.CheckedRequest
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

//go:generate mockgen -destination=mocks/mock_template_store.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/server TemplateStore
type TemplateStore interface {
	RenderDenied(data template.DeniedTemplateData) (string, error)
	RenderCaptcha(data template.CaptchaTemplateData) (string, error)
}

type Captcha = bouncer.CaptchaService
