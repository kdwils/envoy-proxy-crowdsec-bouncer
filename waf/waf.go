package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/types"
)

type Config struct {
	APIKey  string
	APIURL  string
	Timeout time.Duration
}

type WAF struct {
	APIKey      string
	APIURL      string
	apiURL      *url.URL
	http        types.HTTPClient
	httpTimeout time.Duration
}

type WAFResponse struct {
	Action          string              `json:"action"`
	HTTPStatus      int                 `json:"http_status,omitempty"`
	UserBodyContent string              `json:"user_body_content,omitempty"`
	UserCookies     []string            `json:"user_cookies,omitempty"`
	UserHeaders     map[string][]string `json:"user_headers,omitempty"`
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

func NewWAF(appsecURL, apiKey string, httpTimeout time.Duration, http types.HTTPClient) (WAF, error) {
	apiURL, err := url.Parse(appsecURL)
	if err != nil {
		return WAF{}, fmt.Errorf("failed to parse API URL: %w", err)
	}
	return WAF{
		APIURL:      appsecURL,
		apiURL:      apiURL,
		http:        http,
		APIKey:      apiKey,
		httpTimeout: httpTimeout,
	}, nil
}

// Inspect forwards the request to the CrowdSec AppSec component and returns the action.
// The call is bounded by the configured timeout via context cancellation, so a hung
// AppSec instance surfaces as an error instead of stalling the request indefinitely.
func (w WAF) Inspect(ctx context.Context, req AppSecRequest) (WAFResponse, error) {
	logger := logger.FromContext(ctx).With(slog.String("component", "waf"))
	var result WAFResponse
	if req.Method == "" {
		return result, fmt.Errorf("method cannot be empty")
	}

	ctx, cancel := context.WithTimeout(ctx, w.httpTimeout)
	defer cancel()

	forwardReq := newForwardRequest(ctx, w.apiURL, req, w.APIKey)

	resp, err := w.http.Do(forwardReq)
	if err != nil {
		logger.Debug("failed to forward request to CrowdSec", "url", forwardReq.URL.String(), "method", forwardReq.Method, "error", err)
		return result, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("failed to read CrowdSec response", "url", forwardReq.URL.String(), "method", forwardReq.Method, "error", err)
		return result, err
	}

	err = json.Unmarshal(b, &result)
	if err != nil {
		logger.Debug("failed to parse CrowdSec response", "error", err)
		return result, err
	}

	return result, nil
}

func newForwardRequest(ctx context.Context, apiURL *url.URL, request AppSecRequest, apiKey string) *http.Request {
	headers := make(http.Header, len(request.Headers)+7)
	for k, v := range request.Headers {
		if len(k) > 0 && k[0] == ':' {
			continue
		}
		headers.Set(k, v)
	}

	headers.Set("X-Crowdsec-Appsec-Ip", request.RealIP)
	headers.Set("X-Crowdsec-Appsec-Uri", request.URL.Path)
	headers.Set("X-Crowdsec-Appsec-Host", request.URL.Host)
	headers.Set("X-Crowdsec-Appsec-Verb", request.Method)
	headers.Set("X-Crowdsec-Appsec-Api-Key", apiKey)
	headers.Set("X-Crowdsec-Appsec-User-Agent", request.Headers["user-agent"])
	if request.ProtoMajor > 0 {
		headers.Set("X-Crowdsec-Appsec-Http-Version", strconv.Itoa(request.ProtoMajor)+strconv.Itoa(request.ProtoMinor))
	}

	httpRequest := &http.Request{
		Method: http.MethodGet,
		URL:    apiURL,
		Host:   apiURL.Host,
		Header: headers,
		Body:   http.NoBody,
	}

	if len(request.Body) > 0 {
		httpRequest.Method = http.MethodPost
		httpRequest.Body = io.NopCloser(bytes.NewReader(request.Body))
		httpRequest.ContentLength = int64(len(request.Body))
		httpRequest.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(request.Body)), nil
		}
	}

	return httpRequest.WithContext(ctx)
}
