package components

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	APIKey  string
	APIURL  string
	Timeout time.Duration
}

type WAF struct {
	Enabled bool
	APIKey  string
	APIURL  string
	Timeout time.Duration
	config  Config
	http    CrowdsecClient
}

type WAFResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func NewWAF(apiKey, apiURL string, http CrowdsecClient) WAF {
	return WAF{
		APIKey: apiKey,
		APIURL: apiURL,
		http:   http,
	}
}

// Inspect forwards the request to the CrowdSec AppSec component and returns the action.
func (w WAF) Inspect(ctx context.Context, req *http.Request, realIP string) (WAFResponse, error) {
	var result WAFResponse

	// Extract information from the incoming request
	uri := req.URL.Path
	if req.URL.RawQuery != "" {
		uri += "?" + req.URL.RawQuery
	}
	host := req.Host
	method := req.Method
	userAgent := req.Header.Get("User-Agent")
	httpVersion := req.Proto

	// Create request to CrowdSec AppSec component - AppSec runs on a separate port (4241 by default)
	// Parse the main API URL and change the port to AppSec port 4241
	apiURL, err := url.Parse(w.APIURL)
	if err != nil {
		return result, fmt.Errorf("failed to parse API URL: %w", err)
	}

	// Extract host without port and use AppSec port 4241
	hostPart := apiURL.Hostname() // This handles URLs with or without ports
	appSecURL := fmt.Sprintf("%s://%s:4241", apiURL.Scheme, hostPart)

	forwardReq, err := http.NewRequest(req.Method, appSecURL, req.Body)
	if err != nil {
		return result, fmt.Errorf("failed to create request to CrowdSec: %w", err)
	}

	// Copy original headers
	for k, v := range req.Header {
		forwardReq.Header[k] = v
	}

	// Add required CrowdSec AppSec headers
	for k, v := range buildAppSecHeaders(realIP, uri, host, method, w.APIKey, userAgent, httpVersion) {
		forwardReq.Header.Set(k, v)
	}

	resp, err := w.http.Do(ctx, forwardReq, req.Body)
	if err != nil {
		return result, err
	}
	response := resp.Response
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("unexpected status: %v", response.Status)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(b, &result)
	return result, err
}

// buildAppSecHeaders returns a map of the required CrowdSec AppSec headers for the outgoing request.
func buildAppSecHeaders(realIP, uri, host, method, apiKey, userAgent, httpVersion string) map[string]string {
	return map[string]string{
		"X-Crowdsec-Appsec-Ip":           realIP,
		"X-Crowdsec-Appsec-Uri":          uri,
		"X-Crowdsec-Appsec-Host":         host,
		"X-Crowdsec-Appsec-Verb":         method,
		"X-Crowdsec-Appsec-Api-Key":      apiKey,
		"X-Crowdsec-Appsec-User-Agent":   userAgent,
		"X-Crowdsec-Appsec-Http-Version": httpVersion,
	}
}
