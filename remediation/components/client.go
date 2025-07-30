package components

import (
	"context"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

//go:generate mockgen -destination=mocks/mock_crowdsec_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation/components CrowdsecClient
type CrowdsecClient interface {
	Do(ctx context.Context, req *http.Request, v any) (*apiclient.Response, error)
}
