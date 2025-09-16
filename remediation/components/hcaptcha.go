package components

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HCaptchaProvider implements hCaptcha verification
type HCaptchaProvider struct {
	SecretKey  string
	HTTPClient HTTPClient
}

// HCaptchaResponse represents hCaptcha API response
type HCaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTs string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Credit      bool     `json:"credit"`
	ErrorCodes  []string `json:"error-codes"`
}

// NewHCaptchaProvider creates a new hCaptcha provider
func NewHCaptchaProvider(secretKey string, httpClient HTTPClient) (*HCaptchaProvider, error) {
	return &HCaptchaProvider{
		SecretKey:  secretKey,
		HTTPClient: httpClient,
	}, nil
}

// Verify verifies an hCaptcha response token
func (h *HCaptchaProvider) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	data := url.Values{
		"secret":   {h.SecretKey},
		"response": {response},
		"remoteip": {remoteIP},
	}

	url := url.URL{
		Scheme: "https",
		Host:   "hcaptcha.com",
		Path:   "/siteverify",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		url.String(),
		strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create hcaptcha verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("hcaptcha verification request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hcaptcha API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read hcaptcha response: %w", err)
	}

	var result HCaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse hcaptcha response: %w", err)
	}

	if !result.Success && len(result.ErrorCodes) > 0 {
		return false, fmt.Errorf("hcaptcha verification failed: %v", result.ErrorCodes)
	}

	return result.Success, nil
}

// GetProviderName returns the provider name
func (h *HCaptchaProvider) GetProviderName() string {
	return "hcaptcha"
}

// RenderChallenge renders the hCaptcha challenge HTML
func (h *HCaptchaProvider) RenderChallenge(siteKey, callbackURL, redirectURL, sessionID string) (string, error) {
	return RenderCaptchaTemplate("hcaptcha", siteKey, callbackURL, redirectURL, sessionID)
}
