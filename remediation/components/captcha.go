package components

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/config"
)

//go:embed templates/captcha.html
var captchaTemplate string

//go:generate mockgen -destination=mocks/mock_captcha_provider.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation/components CaptchaProvider

// CaptchaProvider defines the interface for captcha verification providers
type CaptchaProvider interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	GetProviderName() string
	RenderChallenge(siteKey, callbackURL, redirectURL, sessionID string) (string, error)
}

// CaptchaSession represents a captcha challenge session
type CaptchaSession struct {
	IP          string
	OriginalURL string
	CreatedAt   time.Time
	Verified    bool
}

// CaptchaService handles captcha verification and challenge management
type CaptchaService struct {
	Config       config.Captcha
	Provider     CaptchaProvider
	Cache        *cache.Cache[time.Time]
	SessionCache *cache.Cache[CaptchaSession]
}

// VerificationRequest represents a captcha verification request
type VerificationRequest struct {
	Token    string `json:"token"`
	Response string `json:"response"`
	IP       string `json:"ip"`
}

// VerificationResult represents the result of captcha verification
type VerificationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// NewCaptchaService creates a new captcha service with the specified configuration
func NewCaptchaService(cfg config.Captcha, httpClient HTTPClient) (*CaptchaService, error) {
	service := &CaptchaService{
		Config:       cfg,
		Cache:        cache.New[time.Time](),
		SessionCache: cache.New[CaptchaSession](),
	}

	if !cfg.Enabled {
		return service, nil
	}

	var provider CaptchaProvider
	var err error

	switch cfg.Provider {
	case "recaptcha":
		provider, err = NewRecaptchaProvider(cfg.SecretKey, httpClient)
	case "hcaptcha":
		provider, err = NewHCaptchaProvider(cfg.SecretKey, httpClient)
	case "turnstile":
		provider, err = NewTurnstileProvider(cfg.SecretKey, httpClient)
	default:
		return nil, fmt.Errorf("unsupported captcha provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create captcha provider: %w", err)
	}

	service.Provider = provider
	return service, nil
}

// StartCleanup starts the cache cleanup routine
func (s *CaptchaService) StartCleanup(ctx context.Context) {
	go s.Cache.Cleanup(ctx, func(key string, expiry time.Time) bool {
		return time.Now().After(expiry)
	})
	go s.SessionCache.Cleanup(ctx, func(key string, session CaptchaSession) bool {
		return time.Now().After(session.CreatedAt.Add(10 * time.Minute))
	})
}

// RequiresCaptcha determines if an IP needs to complete a captcha challenge
func (s *CaptchaService) RequiresCaptcha(ip string) bool {
	if !s.Config.Enabled {
		return false
	}

	expiry, exists := s.Cache.Get(ip)
	if !exists {
		return true
	}

	return time.Now().After(expiry)
}

// VerifyResponse verifies a captcha response from the user
func (s *CaptchaService) VerifyResponse(ctx context.Context, req VerificationRequest) (*VerificationResult, error) {
	if !s.Config.Enabled {
		return &VerificationResult{
			Success: true,
			Message: "Captcha verification disabled",
		}, nil
	}

	success, err := s.Provider.Verify(ctx, req.Response, req.IP)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Message: "Captcha verification failed",
		}, err
	}

	if !success {
		return &VerificationResult{
			Success: false,
			Message: "Captcha verification failed",
		}, nil

	}

	s.Cache.Set(req.IP, time.Now().Add(s.Config.CacheDuration))
	return &VerificationResult{
		Success: true,
		Message: "Captcha verified successfully",
	}, nil
}

// CreateSession creates a new captcha session and returns the session ID
func (s *CaptchaService) CreateSession(ip, originalURL string) (string, error) {
	sessionID, err := generateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}

	session := CaptchaSession{
		IP:          ip,
		OriginalURL: originalURL,
		CreatedAt:   time.Now(),
		Verified:    false,
	}

	s.SessionCache.Set(sessionID, session)
	return sessionID, nil
}

// GetSession retrieves a session by ID
func (s *CaptchaService) GetSession(sessionID string) (*CaptchaSession, bool) {
	session, exists := s.SessionCache.Get(sessionID)
	if !exists {
		return nil, false
	}

	// Check if session is expired (10 minutes)
	if time.Now().After(session.CreatedAt.Add(10 * time.Minute)) {
		s.SessionCache.Delete(sessionID)
		return nil, false
	}

	return &session, true
}

// MarkSessionVerified marks a session as verified
func (s *CaptchaService) MarkSessionVerified(sessionID string) bool {
	session, exists := s.GetSession(sessionID)
	if !exists {
		return false
	}

	session.Verified = true
	s.SessionCache.Set(sessionID, *session)
	return true
}

// GetVerifiedSessionForIP returns a verified session for the given IP
func (s *CaptchaService) GetVerifiedSessionForIP(ip string) *CaptchaSession {
	_, ok := s.Cache.Get(ip)
	if !ok {
		return nil
	}
	return &CaptchaSession{
		IP:       ip,
		Verified: true,
	}
}

// DeleteSession removes a session
func (s *CaptchaService) DeleteSession(sessionID string) {
	s.SessionCache.Delete(sessionID)
}

func (s *CaptchaService) GetProviderName() string {
	return s.Provider.GetProviderName()
}

// CaptchaTemplateData contains data for rendering captcha templates
type CaptchaTemplateData struct {
	Provider    string
	SiteKey     string
	CallbackURL string
	RedirectURL string
	SessionID   string
}

// RenderCaptchaTemplate renders the unified captcha template with provider-specific data
func RenderCaptchaTemplate(provider, siteKey, callbackURL, redirectURL, sessionID string) (string, error) {
	tmpl, err := template.New("captcha").Parse(captchaTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse captcha template: %w", err)
	}

	data := CaptchaTemplateData{
		Provider:    provider,
		SiteKey:     siteKey,
		CallbackURL: callbackURL,
		RedirectURL: redirectURL,
		SessionID:   sessionID,
	}

	var result strings.Builder
	if err := tmpl.Execute(&result, data); err != nil {
		return "", fmt.Errorf("failed to execute captcha template: %w", err)
	}

	return result.String(), nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
