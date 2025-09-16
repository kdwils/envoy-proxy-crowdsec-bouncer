package components

import "net/http"

//go:generate mockgen -destination=mocks/mock_http_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation/components HTTPClient
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
