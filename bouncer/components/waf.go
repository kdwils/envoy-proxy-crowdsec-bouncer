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
	"strconv"
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
	apiURL *url.URL
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

func NewWAF(appsecURL, apiKey string, http *http.Client) (WAF, error) {
	apiURL, err := url.Parse(appsecURL)
	if err != nil {
		return WAF{}, fmt.Errorf("failed to parse API URL: %w", err)
	}
	return WAF{
		APIURL: appsecURL,
		apiURL: apiURL,
		http:   http,
		APIKey: apiKey,
	}, nil
}

// Inspect forwards the request to the CrowdSec AppSec component and returns the action.
func (w WAF) Inspect(ctx context.Context, req AppSecRequest) (WAFResponse, error) {
	logger := logger.FromContext(ctx).With(slog.String("component", "waf"))
	var result WAFResponse
	if req.Method == "" {
		return result, fmt.Errorf("method cannot be empty")
	}

	forwardReq := newForwardRequest(ctx, w.apiURL, req, w.APIKey)

	resp, err := w.http.Do(forwardReq)
	if err != nil {
		logger.Debug("failed to forward request to CrowdSec", "url", forwardReq.URL.String(), "method", forwardReq.Method, "headers", forwardReq.Header, "error", err)
		return result, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("failed to read CrowdSec response", "url", forwardReq.URL.String(), "method", forwardReq.Method, "headers", forwardReq.Header, "error", err)
		return result, err
	}

	err = json.Unmarshal(b, &result)
	if err != nil {
		logger.Debug("failed to parse CrowdSec response", "body", string(b), "error", err)
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
