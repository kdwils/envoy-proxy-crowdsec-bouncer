package crowdsec

import (
	"net/http"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

func NewClient(apiKey string, apiURL string, userAgent string) (*apiclient.ApiClient, error) {
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
