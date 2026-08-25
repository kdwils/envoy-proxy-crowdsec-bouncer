package types

import (
	"net/http"
)

//go:generate mockgen -destination=mocks/mock_http_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/types HTTPClient
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
