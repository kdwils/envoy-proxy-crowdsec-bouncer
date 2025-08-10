package components

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"time"
)

//go:generate mockgen -destination=mocks/mock_http.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation/components HTTP
type HTTP interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	APIKey  string
	APIURL  string
	Timeout time.Duration
}

type WAF struct {
	APIKey string
	APIURL string
	http   HTTP
}

type WAFResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func NewWAF(appsecURL, apiKey string, http *http.Client) WAF {
	return WAF{
		APIURL: appsecURL,
		http:   http,
		APIKey: apiKey,
	}
}

// Inspect forwards the request to the CrowdSec AppSec component and returns the action.
func (w WAF) Inspect(ctx context.Context, req *http.Request, realIP string) (WAFResponse, error) {
	var result WAFResponse
	if req == nil {
		return result, fmt.Errorf("request cannot be nil")
	}
	if req.Header == nil {
		return result, fmt.Errorf("request headers cannot be nil")
	}

	apiURL, err := url.Parse(w.APIURL)
	if err != nil {
		return result, fmt.Errorf("failed to parse API URL: %w", err)
	}

	method := http.MethodGet
	if req.Body != nil {
		method = http.MethodPost
	}

	forwardReq, err := http.NewRequestWithContext(ctx, method, apiURL.String(), req.Body)
	if err != nil {
		return result, fmt.Errorf("failed to create request to CrowdSec: %w", err)
	}

	maps.Copy(forwardReq.Header, req.Header)

	for k, v := range buildAppSecHeaders(req, realIP, w.APIKey) {
		forwardReq.Header.Set(k, v)
	}

	resp, err := w.http.Do(forwardReq)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("unexpected status: %v", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(b, &result)
	return result, err
}

// buildAppSecHeaders returns a map of the required CrowdSec AppSec headers for the outgoing request.
func buildAppSecHeaders(req *http.Request, realIP, apiKey string) map[string]string {
	return map[string]string{
		"X-Crowdsec-Appsec-Ip":           realIP,
		"X-Crowdsec-Appsec-Uri":          req.URL.Path,
		"X-Crowdsec-Appsec-Host":         req.URL.Host,
		"X-Crowdsec-Appsec-Verb":         req.Method,
		"X-Crowdsec-Appsec-Api-Key":      apiKey,
		"X-Crowdsec-Appsec-User-Agent":   req.Header.Get("User-Agent"),
		"X-Crowdsec-Appsec-Http-Version": req.Proto,
	}
}
