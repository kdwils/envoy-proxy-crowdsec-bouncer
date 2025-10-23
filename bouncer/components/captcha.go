package components

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/token"
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
	CSRFToken    string
}

// CaptchaService handles captcha verification and challenge management
type CaptchaService struct {
	Config         config.Captcha
	Provider       CaptchaProvider
	RequestTimeout time.Duration
	generateToken  func() (string, error)
	nowFunc        func() time.Time
	jwt            *token.JWT
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
	Token   string `json:"token,omitempty"`
}

// NewCaptchaService creates a new captcha service with the specified configuration
func NewCaptchaService(cfg config.Captcha, httpClient HTTPClient) (*CaptchaService, error) {
	if cfg.Enabled && cfg.SigningKey == "" {
		return nil, fmt.Errorf("signing key is required when captcha is enabled")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	service := &CaptchaService{
		Config:         cfg,
		RequestTimeout: timeout,
		generateToken:  generateSecureToken,
		nowFunc:        time.Now,
		jwt:            token.NewJWT(cfg.SigningKey),
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

// RequiresCaptcha determines if an IP needs to complete a captcha challenge
func (s *CaptchaService) RequiresCaptcha(ip, verificationToken string) bool {
	if verificationToken == "" {
		return true
	}

	claims, err := s.jwt.VerifyVerificationToken(verificationToken)
	if err != nil {
		return true
	}

	if claims.IP != ip {
		return true
	}

	return false
}

// VerifyResponse verifies a captcha response from the user
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

	now := s.nowFunc()
	verificationClaims := token.VerificationClaims{
		IP:         req.IP,
		VerifiedAt: now,
		ExpiresAt:  now.Add(s.Config.SessionDuration),
	}

	verificationToken, err := s.jwt.CreateVerificationToken(verificationClaims)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Message: "Failed to create verification token",
		}, fmt.Errorf("failed to create verification token: %w", err)
	}

	return &VerificationResult{
		Success: true,
		Message: "Captcha verified successfully",
		Token:   verificationToken,
	}, nil
}

// GetSession retrieves a session by ID (JWT token)
func (s *CaptchaService) GetSession(sessionID string) (*CaptchaSession, bool) {
	claims, err := s.jwt.VerifyToken(sessionID)
	if err != nil {
		return nil, false
	}

	callbackURL := s.Config.CallbackURL + "/captcha"

	redirectParams := make(url.Values)
	redirectParams.Set("session", sessionID)
	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()

	session := &CaptchaSession{
		IP:           claims.IP,
		ID:           sessionID,
		OriginalURL:  claims.OriginalURL,
		CreatedAt:    claims.CreatedAt,
		ExpiresAt:    claims.ExpiresAt,
		Provider:     claims.Provider,
		SiteKey:      claims.SiteKey,
		CallbackURL:  callbackURL,
		RedirectURL:  claims.OriginalURL,
		ChallengeURL: challengeURL,
		CSRFToken:    claims.CSRFToken,
	}

	return session, true
}

func (s *CaptchaService) GetProviderName() string {
	return s.Provider.GetProviderName()
}

func (s *CaptchaService) IsEnabled() bool {
	return s.Config.Enabled
}

// CreateSession creates a new session for an ip if required, otherwise returns nil
func (s *CaptchaService) CreateSession(ip, originalURL, verificationToken string) (*CaptchaSession, error) {
	if !s.RequiresCaptcha(ip, verificationToken) {
		return nil, nil
	}

	if !isValidRedirectURL(originalURL) {
		return nil, fmt.Errorf("invalid redirect URL: %s", originalURL)
	}

	csrfToken, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	t := s.nowFunc()
	providerName := s.Provider.GetProviderName()

	claims := token.SessionClaims{
		IP:          ip,
		OriginalURL: originalURL,
		CreatedAt:   t,
		ExpiresAt:   t.Add(s.Config.ChallengeDuration),
		Provider:    providerName,
		SiteKey:     s.Config.SiteKey,
		CSRFToken:   csrfToken,
	}

	sessionID, err := s.jwt.CreateToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create session token: %w", err)
	}

	redirectParams := make(url.Values)
	redirectParams.Set("session", sessionID)

	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()

	callbackURL := s.Config.CallbackURL + "/captcha"

	session := CaptchaSession{
		IP:           ip,
		Provider:     providerName,
		SiteKey:      s.Config.SiteKey,
		CallbackURL:  callbackURL,
		OriginalURL:  originalURL,
		RedirectURL:  originalURL,
		ChallengeURL: challengeURL,
		ID:           sessionID,
		CreatedAt:    t,
		ExpiresAt:    t.Add(s.Config.ChallengeDuration),
		CSRFToken:    csrfToken,
	}

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

func isValidRedirectURL(redirectURL string) bool {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	if parsed.Host == "" {
		return false
	}

	return true
}
