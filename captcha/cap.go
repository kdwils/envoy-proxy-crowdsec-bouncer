package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kdwils/envoy-proxy-bouncer/types"
)

// CapProvider implements verification for a self-hosted Cap (trycap.dev) instance
type CapProvider struct {
	ServerURL  string
	SiteKey    string
	SecretKey  string
	HTTPClient types.HTTPClient
}

// capVerifyRequest is the JSON body Cap's siteverify endpoint expects
type capVerifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
}

// CapResponse represents a Cap siteverify API response
type CapResponse struct {
	Success bool `json:"success"`
}

// NewCapProvider creates a new Cap provider
func NewCapProvider(serverURL, siteKey, secretKey string, httpClient types.HTTPClient) (*CapProvider, error) {
	return &CapProvider{
		ServerURL:  serverURL,
		SiteKey:    siteKey,
		SecretKey:  secretKey,
		HTTPClient: httpClient,
	}, nil
}

// Verify verifies a Cap response token. Cap's siteverify API has no remoteip
// parameter, unlike reCAPTCHA/Turnstile, so remoteIP is unused here.
func (c *CapProvider) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	body, err := json.Marshal(capVerifyRequest{
		Secret:   c.SecretKey,
		Response: response,
	})
	if err != nil {
		return false, fmt.Errorf("failed to build cap verification request: %w", err)
	}

	verifyURL, err := url.JoinPath(c.ServerURL, c.SiteKey, "siteverify")
	if err != nil {
		return false, fmt.Errorf("failed to build cap verification url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to create cap verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("cap verification request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("cap API returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read cap response: %w", err)
	}

	var result CapResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, fmt.Errorf("failed to parse cap response: %w", err)
	}

	return result.Success, nil
}

// GetProviderName returns the provider name
func (c *CapProvider) GetProviderName() string {
	return "cap"
}
