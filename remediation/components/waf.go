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

type Config struct {
	APIKey  string
	APIURL  string
	Timeout time.Duration
}

type WAF struct {
	APIKey string
	APIURL string
	http   HTTPClient
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
func (w WAF) Inspect(ctx context.Context, req AppSecRequest) (WAFResponse, error) {
	logger := logger.FromContext(ctx).With(slog.String("component", "waf"))
	var result WAFResponse
	if req.Method == "" {
		return result, fmt.Errorf("method cannot be empty")
	}

	apiURL, err := url.Parse(w.APIURL)
	if err != nil {
		logger.Error("failed to parse API URL", slog.String("url", w.APIURL), slog.Any("error", err))
		return result, fmt.Errorf("failed to parse API URL: %w", err)
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	forwardReqMethod := http.MethodGet
	if req.Body != nil {
		forwardReqMethod = http.MethodPost
	}

	forwardReq, err := http.NewRequestWithContext(ctx, forwardReqMethod, apiURL.String(), bodyReader)
	if err != nil {
		return result, fmt.Errorf("failed to create request to CrowdSec: %w", err)
	}

	forwardReq.Header = make(http.Header)
	for k, v := range req.Headers {
		if len(k) > 0 && k[0] == ':' {
			continue
		}
		forwardReq.Header.Set(k, v)
	}

	for k, v := range buildAppSecHeaders(req, req.RealIP, w.APIKey) {
		forwardReq.Header.Set(k, v)
	}

	logger.Debug("forwarding request to CrowdSec", "url", forwardReq.URL.String(), "method", forwardReq.Method, "headers", forwardReq.Header)

	resp, err := w.http.Do(forwardReq)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(b, &result)
	return result, err
}

// buildAppSecHeaders returns a map of the required CrowdSec AppSec headers for the outgoing request.
func buildAppSecHeaders(req AppSecRequest, realIP, apiKey string) map[string]string {
	headers := map[string]string{
		"X-Crowdsec-Appsec-Ip":         realIP,
		"X-Crowdsec-Appsec-Uri":        req.URL.Path,
		"X-Crowdsec-Appsec-Host":       req.URL.Host,
		"X-Crowdsec-Appsec-Verb":       req.Method,
		"X-Crowdsec-Appsec-Api-Key":    apiKey,
		"X-Crowdsec-Appsec-User-Agent": req.Headers["User-Agent"],
	}

	if req.ProtoMajor > 0 {
		headers["X-Crowdsec-Appsec-Http-Version"] = fmt.Sprintf("%d%d", req.ProtoMajor, req.ProtoMinor)
	}

	return headers
}
