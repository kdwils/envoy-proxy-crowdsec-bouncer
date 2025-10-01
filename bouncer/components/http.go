package components

import (
	"net/http"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

//go:generate mockgen -destination=mocks/mock_http_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer/components HTTPClient
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

func NewCrowdsecClient(apiKey string, apiURL string, userAgent string) (*apiclient.ApiClient, error) {
	if apiURL[len(apiURL)-1] != '/' {
		apiURL += "/"
	}

	url, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	transport := &apiclient.APIKeyTransport{
		APIKey: apiKey,
	}

	http := http.Client{Transport: transport}

	return apiclient.NewDefaultClient(url, "v1", userAgent, &http)
}
