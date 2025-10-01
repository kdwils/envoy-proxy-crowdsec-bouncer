package components

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/config"
)

//go:generate mockgen -destination=mocks/mock_captcha_provider.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer/components CaptchaProvider

// CaptchaProvider defines the interface for captcha verification providers
type CaptchaProvider interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	GetProviderName() string
}

// CaptchaSession represents a captcha challenge session
type CaptchaSession struct {
	IP           string
	ID           string
	OriginalURL  string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Provider     string
	SiteKey      string
	CallbackURL  string
	RedirectURL  string
	ChallengeURL string
}

// CaptchaService handles captcha verification and challenge management
type CaptchaService struct {
	Config                config.Captcha
	Provider              CaptchaProvider
	VerifiedCache         *cache.Cache[time.Time]
	ChallengeSessionCache *cache.Cache[CaptchaSession]
	RequestTimeout        time.Duration
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
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	service := &CaptchaService{
		Config:                cfg,
		VerifiedCache:         cache.New(cache.WithCleanupInterval[time.Time](cfg.SessionDuration)),
		ChallengeSessionCache: cache.New(cache.WithCleanupInterval[CaptchaSession](cfg.ChallengeDuration)),
		RequestTimeout:        timeout,
	}

	if !cfg.Enabled {
		return service, nil
	}

	var provider CaptchaProvider
	var err error

	switch cfg.Provider {
	case "recaptcha":
		provider, err = NewRecaptchaProvider(cfg.SecretKey, httpClient)
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
	go s.VerifiedCache.Cleanup(ctx, func(key string, expiry time.Time) bool {
		return time.Now().After(expiry)
	})
	go s.ChallengeSessionCache.Cleanup(ctx, func(key string, session CaptchaSession) bool {
		return time.Now().After(session.ExpiresAt)
	})
}

// RequiresCaptcha determines if an IP needs to complete a captcha challenge
func (s *CaptchaService) RequiresCaptcha(ip string) bool {
	expiry, exists := s.VerifiedCache.Get(ip)
	if !exists {
		return true
	}

	return time.Now().After(expiry)
}

// VerifyResponse verifies a captcha response from the user and deletes the challenge session from the cache if successful
func (s *CaptchaService) VerifyResponse(ctx context.Context, sessionID string, req VerificationRequest) (*VerificationResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, s.RequestTimeout)
	defer cancel()

	success, err := s.Provider.Verify(timeoutCtx, req.Response, req.IP)
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

	s.VerifiedCache.Set(req.IP, time.Now().Add(s.Config.SessionDuration))
	s.ChallengeSessionCache.Delete(sessionID)

	return &VerificationResult{
		Success: true,
		Message: "Captcha verified successfully",
	}, nil
}

// GetSession retrieves a session by ID
func (s *CaptchaService) GetSession(sessionID string) (*CaptchaSession, bool) {
	session, exists := s.ChallengeSessionCache.Get(sessionID)
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		s.ChallengeSessionCache.Delete(sessionID)
		return nil, false
	}

	return &session, true
}

// DeleteSession removes a session
func (s *CaptchaService) DeleteSession(sessionID string) {
	s.ChallengeSessionCache.Delete(sessionID)
}

func (s *CaptchaService) GetProviderName() string {
	return s.Provider.GetProviderName()
}

func (s *CaptchaService) IsEnabled() bool {
	return s.Config.Enabled
}

// CreateSession creates a new session for an ip if required, otherwise returns nil
func (s *CaptchaService) CreateSession(ip, originalURL string) (*CaptchaSession, error) {
	if !s.RequiresCaptcha(ip) {
		return nil, nil
	}

	sessionID, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	redirectParams := make(url.Values)
	redirectParams.Set("session", sessionID)

	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()

	callbackURL := s.Config.CallbackURL + "/captcha"

	t := time.Now()

	session := CaptchaSession{
		IP:           ip,
		Provider:     s.Provider.GetProviderName(),
		SiteKey:      s.Config.SiteKey,
		CallbackURL:  callbackURL,
		RedirectURL:  originalURL,
		ChallengeURL: challengeURL,
		ID:           sessionID,
		CreatedAt:    t,
		ExpiresAt:    t.Add(s.Config.ChallengeDuration),
	}

	s.ChallengeSessionCache.Set(sessionID, session)

	return &session, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
