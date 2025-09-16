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

// RecaptchaProvider implements Google reCAPTCHA verification
type RecaptchaProvider struct {
	SecretKey  string
	HTTPClient HTTPClient
}

// RecaptchaResponse represents Google reCAPTCHA API response
type RecaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTs string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// NewRecaptchaProvider creates a new reCAPTCHA provider
func NewRecaptchaProvider(secretKey string, httpClient HTTPClient) (*RecaptchaProvider, error) {
	return &RecaptchaProvider{
		SecretKey:  secretKey,
		HTTPClient: httpClient,
	}, nil
}

// Verify verifies a reCAPTCHA response token
func (r *RecaptchaProvider) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	data := url.Values{
		"secret":   {r.SecretKey},
		"response": {response},
		"remoteip": {remoteIP},
	}

	url := url.URL{
		Scheme: "https",
		Host:   "www.google.com",
		Path:   "/api/siteverify",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		url.String(),
		strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to create recaptcha verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("recaptcha verification request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("recaptcha API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read recaptcha response: %w", err)
	}

	var result RecaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse recaptcha response: %w", err)
	}

	if !result.Success && len(result.ErrorCodes) > 0 {
		return false, fmt.Errorf("recaptcha verification failed: %v", result.ErrorCodes)
	}

	return result.Success, nil
}

// GetProviderName returns the provider name
func (r *RecaptchaProvider) GetProviderName() string {
	return "recaptcha"
}

// RenderChallenge renders the reCAPTCHA challenge HTML
func (r *RecaptchaProvider) RenderChallenge(siteKey, callbackURL, redirectURL, sessionID string) (string, error) {
	return RenderCaptchaTemplate("recaptcha", siteKey, callbackURL, redirectURL, sessionID)
}
