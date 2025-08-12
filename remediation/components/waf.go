package components

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/logger"
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

// AppSecRequest is a light DTO used to forward the original request data to AppSec.
type AppSecRequest struct {
	Method     string
	URL        url.URL
	Headers    map[string]string
	Body       []byte
	RealIP     string
	ProtoMajor int
	ProtoMinor int
}

func NewWAF(appsecURL, apiKey string, http *http.Client) WAF {
	return WAF{
		APIURL: appsecURL,
		http:   http,
		APIKey: apiKey,
	}
}

// Inspect forwards the request to the CrowdSec AppSec component and returns the action.
func (w WAF) Inspect(ctx context.Context, areq AppSecRequest) (WAFResponse, error) {
	logger := logger.FromContext(ctx).With(slog.String("component", "waf"))
	var result WAFResponse
	// validate basics
	if areq.Method == "" {
		return result, fmt.Errorf("method cannot be empty")
	}

	apiURL, err := url.Parse(w.APIURL)
	if err != nil {
		logger.Error("failed to parse API URL", slog.String("url", w.APIURL), slog.Any("error", err))
		return result, fmt.Errorf("failed to parse API URL: %w", err)
	}

	var bodyReader io.Reader
	if len(areq.Body) > 0 {
		bodyReader = bytes.NewReader(areq.Body)
	}

	forwardReq, err := http.NewRequestWithContext(ctx, areq.Method, apiURL.String(), bodyReader)
	if err != nil {
		return result, fmt.Errorf("failed to create request to CrowdSec: %w", err)
	}
	// copy headers, excluding any pseudo-headers
	forwardReq.Header = make(http.Header)
	for k, v := range areq.Headers {
		if len(k) > 0 && k[0] == ':' {
			continue
		}
		forwardReq.Header.Set(k, v)
	}

	// set protocol version when available
	if areq.ProtoMajor > 0 {
		forwardReq.ProtoMajor = areq.ProtoMajor
		forwardReq.ProtoMinor = areq.ProtoMinor
	}

	// add AppSec specific headers
	for k, v := range buildAppSecHeaders(forwardReq, areq.RealIP, w.APIKey) {
		forwardReq.Header.Set(k, v)
	}

	logger.Debug("forwarding request to CrowdSec", "url", apiURL.String(), "method", areq.Method, "headers", forwardReq.Header)

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
		"X-Crowdsec-Appsec-Http-Version": fmt.Sprintf("%d%d", req.ProtoMajor, req.ProtoMinor),
	}
}
