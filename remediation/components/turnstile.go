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

// TurnstileProvider implements Cloudflare Turnstile verification
type TurnstileProvider struct {
	SecretKey  string
	HTTPClient HTTPClient
}

// TurnstileResponse represents Cloudflare Turnstile API response
type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTs string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// NewTurnstileProvider creates a new Turnstile provider
func NewTurnstileProvider(secretKey string, httpClient HTTPClient) (*TurnstileProvider, error) {
	return &TurnstileProvider{
		SecretKey:  secretKey,
		HTTPClient: httpClient,
	}, nil
}

// Verify verifies a Turnstile response token
func (t *TurnstileProvider) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	data := url.Values{
		"secret":   {t.SecretKey},
		"response": {response},
		"remoteip": {remoteIP},
	}

	url := url.URL{
		Scheme: "https",
		Host:   "challenges.cloudflare.com",
		Path:   "/turnstile/v0/siteverify",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		url.String(),
		strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create turnstile verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("turnstile verification request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("turnstile API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read turnstile response: %w", err)
	}

	var result TurnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse turnstile response: %w", err)
	}

	if !result.Success && len(result.ErrorCodes) > 0 {
		return false, fmt.Errorf("turnstile verification failed: %v", result.ErrorCodes)
	}

	return result.Success, nil
}

// GetProviderName returns the provider name
func (t *TurnstileProvider) GetProviderName() string {
	return "turnstile"
}

// RenderChallenge renders the Turnstile challenge HTML
func (t *TurnstileProvider) RenderChallenge(siteKey, callbackURL, redirectURL, sessionID string) (string, error) {
	return RenderCaptchaTemplate("turnstile", siteKey, callbackURL, redirectURL, sessionID)
}
