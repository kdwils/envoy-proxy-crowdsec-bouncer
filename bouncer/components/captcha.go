package components

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdwils/envoy-proxy-bouncer/config"
)

//go:generate mockgen -destination=mocks/mock_captcha_provider.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer/components CaptchaProvider

type CaptchaProvider interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	GetProviderName() string
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

type ChallengeClaims struct {
	IP          string `json:"ip"`
	OriginalURL string `json:"original_url"`
	CSRFToken   string `json:"csrf_token"`
	jwt.RegisteredClaims
}

type VerificationClaims struct {
	IP string `json:"ip"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	signingKey []byte
}

func NewJWTManager(signingKey string) *JWTManager {
	return &JWTManager{
		signingKey: []byte(signingKey),
	}
}

func (j *JWTManager) CreateChallengeToken(claims ChallengeClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.signingKey)
}

func (j *JWTManager) VerifyChallengeToken(tokenString string) (*ChallengeClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ChallengeClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*ChallengeClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (j *JWTManager) CreateVerificationToken(claims VerificationClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.signingKey)
}

func (j *JWTManager) VerifyVerificationToken(tokenString string) (*VerificationClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &VerificationClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*VerificationClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

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

type CaptchaService struct {
	Config         config.Captcha
	Provider       CaptchaProvider
	RequestTimeout time.Duration
	generateToken  func() (string, error)
	nowFunc        func() time.Time
	jwt            *JWTManager
}

type VerificationRequest struct {
	Token    string `json:"token"`
	Response string `json:"response"`
	IP       string `json:"ip"`
}

type VerificationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

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
		nowFunc:        time.Now,
		jwt:            NewJWTManager(cfg.SigningKey),
		generateToken:  generateCSRFToken,
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

func (s *CaptchaService) VerifyResponse(ctx context.Context, challengeToken string, req VerificationRequest) (*VerificationResult, error) {
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
	verificationClaims := VerificationClaims{
		IP: req.IP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.Config.SessionDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	tokenString, err := s.jwt.CreateVerificationToken(verificationClaims)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Message: "Failed to create verification token",
		}, fmt.Errorf("failed to create verification token: %w", err)
	}

	return &VerificationResult{
		Success: true,
		Message: "Captcha verified successfully",
		Token:   tokenString,
	}, nil
}

func (s *CaptchaService) GetSession(challengeToken string) (*CaptchaSession, bool) {
	claims, err := s.jwt.VerifyChallengeToken(challengeToken)
	if err != nil {
		return nil, false
	}

	callbackURL := s.Config.CallbackURL + "/captcha"

	redirectParams := make(url.Values)
	redirectParams.Set("session", challengeToken)
	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()

	createdAt := claims.IssuedAt.Time
	expiresAt := claims.ExpiresAt.Time

	session := &CaptchaSession{
		IP:           claims.IP,
		ID:           challengeToken,
		OriginalURL:  claims.OriginalURL,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
		Provider:     s.Provider.GetProviderName(),
		SiteKey:      s.Config.SiteKey,
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

	now := s.nowFunc()
	expiresAt := now.Add(s.Config.ChallengeDuration)

	claims := ChallengeClaims{
		IP:          ip,
		OriginalURL: originalURL,
		CSRFToken:   csrfToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	challengeToken, err := s.jwt.CreateChallengeToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge token: %w", err)
	}

	redirectParams := make(url.Values)
	redirectParams.Set("session", challengeToken)

	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()
	callbackURL := s.Config.CallbackURL + "/captcha"

	session := CaptchaSession{
		IP:           ip,
		Provider:     s.Provider.GetProviderName(),
		SiteKey:      s.Config.SiteKey,
		CallbackURL:  callbackURL,
		OriginalURL:  originalURL,
		RedirectURL:  originalURL,
		ChallengeURL: challengeURL,
		ID:           challengeToken,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		CSRFToken:    csrfToken,
	}

	return &session, nil
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
