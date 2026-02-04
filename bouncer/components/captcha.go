package components

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
)

//go:generate mockgen -destination=mocks/mock_captcha_provider.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer/components CaptchaProvider

type CaptchaProvider interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	GetProviderName() string
}

var (
	ErrFailedChallenge = errors.New("challenge verification failed")
)

type ChallengeClaims struct {
	IPHash      string `json:"ip"`
	OriginalURL string `json:"ou"`
	jwt.RegisteredClaims
}

type SessionClaims struct {
	SID string `json:"sid"`
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

func (j *JWTManager) ipHashKey(ip string) string {
	mac := hmac.New(sha256.New, j.signingKey)
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

func (j *JWTManager) CreateChallengeToken(originalURL, remoteIP string, now time.Time, challengeTTL time.Duration) (string, *ChallengeClaims, error) {
	claims := ChallengeClaims{
		IPHash:      j.ipHashKey(remoteIP),
		OriginalURL: originalURL,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(challengeTTL)),
		},
	}

	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(j.signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign challenge token: %w", err)
	}

	return tokenStr, &claims, nil
}

func (j *JWTManager) CheckChallengeToken(tokenString string) (*ChallengeClaims, error) {
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

func (j *JWTManager) VerifyIPHash(claims *ChallengeClaims, ip string) bool {
	return hmac.Equal([]byte(claims.IPHash), []byte(j.ipHashKey(ip)))
}

func (j *JWTManager) CreateSessionToken(sessionID string, now time.Time, sessionTTL time.Duration) (string, error) {
	claims := SessionClaims{
		SID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
		},
	}

	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(j.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to create session token: %w", err)
	}
	return tokenStr, nil
}

func (j *JWTManager) VerifySessionToken(tokenString string) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse session token: %v", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid session token")
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("expired session")
	}

	return claims, nil
}

type CaptchaSession struct {
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

type CaptchaService struct {
	Config         config.Captcha
	Provider       CaptchaProvider
	RequestTimeout time.Duration
	nowFunc        func() time.Time
	jwt            *JWTManager
	challengeCache *cache.Cache[ChallengeClaims]
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

	if cfg.Enabled && len(cfg.SigningKey) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	challengeCache := cache.New[ChallengeClaims](
		cache.WithCleanup(time.Minute, func(key string, value ChallengeClaims) bool {
			return value.ExpiresAt.Time.Before(time.Now())
		}),
	)

	service := &CaptchaService{
		Config:         cfg,
		RequestTimeout: timeout,
		nowFunc:        time.Now,
		jwt:            NewJWTManager(cfg.SigningKey),
		challengeCache: challengeCache,
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

func (s *CaptchaService) RequiresCaptcha(sessionToken string) bool {
	if sessionToken == "" {
		return true
	}

	_, err := s.jwt.VerifySessionToken(sessionToken)
	return err != nil
}

func (s *CaptchaService) VerifyResponse(ctx context.Context, ip, challengeToken, challengeResponse string) (*VerificationResult, error) {
	claims, err := s.jwt.CheckChallengeToken(challengeToken)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Message: "Invalid or expired challenge token",
		}, fmt.Errorf("invalid or expired challenge token: %w", err)
	}

	if !s.jwt.VerifyIPHash(claims, ip) {
		return &VerificationResult{
			Success: false,
			Message: "",
		}, fmt.Errorf("challenge IP mismatch")
	}

	if _, ok := s.challengeCache.Get(claims.ID); !ok {
		return &VerificationResult{
			Success: false,
			Message: "Challenge already used or expired",
		}, fmt.Errorf("challenge already used or expired")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, s.RequestTimeout)
	defer cancel()

	success, err := s.Provider.Verify(timeoutCtx, challengeResponse, ip)
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
		}, ErrFailedChallenge
	}

	s.challengeCache.Delete(claims.ID)

	now := s.nowFunc()
	sessionID := uuid.NewString()
	tokenString, err := s.jwt.CreateSessionToken(sessionID, now, s.Config.SessionDuration)
	if err != nil {
		return &VerificationResult{
			Success: false,
			Message: "failed to create session token",
		}, fmt.Errorf("failed to create session token: %w", err)
	}

	return &VerificationResult{
		Success: true,
		Message: "Captcha verified successfully",
		Token:   tokenString,
	}, nil
}

func (s *CaptchaService) GetSession(challengeToken string) (*CaptchaSession, bool) {
	claims, err := s.jwt.CheckChallengeToken(challengeToken)
	if err != nil {
		return nil, false
	}

	callbackURL := s.Config.CallbackURL + "/captcha"

	redirectParams := make(url.Values)
	redirectParams.Set("challengeToken", challengeToken)
	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()

	createdAt := claims.IssuedAt.Time
	expiresAt := claims.ExpiresAt.Time

	session := &CaptchaSession{
		ID:           challengeToken,
		OriginalURL:  claims.OriginalURL,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
		Provider:     s.Provider.GetProviderName(),
		SiteKey:      s.Config.SiteKey,
		CallbackURL:  callbackURL,
		RedirectURL:  claims.OriginalURL,
		ChallengeURL: challengeURL,
	}

	return session, true
}

func (s *CaptchaService) GetProviderName() string {
	return s.Provider.GetProviderName()
}

func (s *CaptchaService) IsEnabled() bool {
	return s.Config.Enabled
}

func (s *CaptchaService) StartCleanup(ctx context.Context) {
	s.challengeCache.StartCleanup(ctx)
}

func (s *CaptchaService) CookieName() string {
	return s.Config.CookieName
}

func (s *CaptchaService) CreateSession(ip, originalURL, sessionToken string) (*CaptchaSession, error) {
	if !s.RequiresCaptcha(sessionToken) {
		return nil, nil
	}

	if !isValidRedirectURL(originalURL) {
		return nil, fmt.Errorf("invalid redirect URL: %s", originalURL)
	}

	now := s.nowFunc()
	challengeToken, claims, err := s.jwt.CreateChallengeToken(originalURL, ip, now, s.Config.ChallengeDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge token: %w", err)
	}

	s.challengeCache.Set(claims.ID, *claims)

	redirectParams := make(url.Values)
	redirectParams.Set("challengeToken", challengeToken)

	challengeURL := s.Config.CallbackURL + "/captcha/challenge?" + redirectParams.Encode()
	callbackURL := s.Config.CallbackURL + "/captcha"

	expiresAt := claims.ExpiresAt.Time

	session := CaptchaSession{
		Provider:     s.Provider.GetProviderName(),
		SiteKey:      s.Config.SiteKey,
		CallbackURL:  callbackURL,
		OriginalURL:  originalURL,
		RedirectURL:  originalURL,
		ChallengeURL: challengeURL,
		ID:           challengeToken,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
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
