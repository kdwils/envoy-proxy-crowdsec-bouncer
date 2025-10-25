package components

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestJWTManager_ChallengeToken(t *testing.T) {
	t.Run("creates and verifies challenge token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		claims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token, err := manager.CreateChallengeToken(claims)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		verifiedClaims, err := manager.VerifyChallengeToken(token)

		require.NoError(t, err)
		require.NotNil(t, verifiedClaims)
		assert.Equal(t, "192.168.1.1", verifiedClaims.IP)
		assert.Equal(t, "http://example.com", verifiedClaims.OriginalURL)
	})

	t.Run("rejects expired challenge token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		claims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			},
		}

		token, err := manager.CreateChallengeToken(claims)
		require.NoError(t, err)

		verifiedClaims, err := manager.VerifyChallengeToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects invalid challenge token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")

		verifiedClaims, err := manager.VerifyChallengeToken("invalid-token")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects challenge token with wrong signing key", func(t *testing.T) {
		manager1 := NewJWTManager("key-1")
		manager2 := NewJWTManager("key-2")

		claims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}

		token, err := manager1.CreateChallengeToken(claims)
		require.NoError(t, err)

		verifiedClaims, err := manager2.VerifyChallengeToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})
}

func TestJWTManager_VerificationToken(t *testing.T) {
	t.Run("creates and verifies verification token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		claims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token, err := manager.CreateVerificationToken(claims)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		verifiedClaims, err := manager.VerifyVerificationToken(token)

		require.NoError(t, err)
		require.NotNil(t, verifiedClaims)
		assert.Equal(t, "192.168.1.1", verifiedClaims.IP)
	})

	t.Run("rejects expired verification token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		claims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			},
		}

		token, err := manager.CreateVerificationToken(claims)
		require.NoError(t, err)

		verifiedClaims, err := manager.VerifyVerificationToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects invalid verification token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")

		verifiedClaims, err := manager.VerifyVerificationToken("invalid-token")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})
}

func TestNewCaptchaService(t *testing.T) {
	t.Run("disabled captcha", func(t *testing.T) {
		cfg := config.Captcha{Enabled: false}

		got, err := NewCaptchaService(cfg, http.DefaultClient)

		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.Equal(t, cfg, got.Config)
		assert.Nil(t, got.Provider)
		assert.NotNil(t, got.jwt)
		assert.Equal(t, 10*time.Second, got.RequestTimeout)
		assert.NotNil(t, got.nowFunc)
	})

	t.Run("recaptcha provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "recaptcha",
			SecretKey:    "test-secret",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)

		require.NoError(t, err)
		require.NotNil(t, service)
		assert.True(t, service.Config.Enabled)
		assert.NotNil(t, service.Provider)
		assert.Equal(t, "recaptcha", service.Provider.GetProviderName())
	})

	t.Run("turnstile provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "turnstile",
			SecretKey:    "test-secret",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)

		require.NoError(t, err)
		require.NotNil(t, service)
		assert.True(t, service.Config.Enabled)
		assert.NotNil(t, service.Provider)
		assert.Equal(t, "turnstile", service.Provider.GetProviderName())
	})

	t.Run("unsupported provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:    true,
			Provider:   "unsupported",
			SigningKey: "test-signing-key-that-is-at-least-32-bytes-long",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)

		assert.Error(t, err)
		assert.Nil(t, service)
	})

	t.Run("missing signing key when enabled", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:  true,
			Provider: "recaptcha",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)

		assert.Error(t, err)
		assert.Nil(t, service)
	})
}

func TestCaptchaService_RequiresCaptcha(t *testing.T) {
	t.Run("no verification token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1", "")

		assert.True(t, got)
	})

	t.Run("expired verification token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		now := time.Now()
		expiredClaims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			},
		}
		expiredToken, err := service.jwt.CreateVerificationToken(expiredClaims)
		require.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1", expiredToken)

		assert.True(t, got)
	})

	t.Run("valid verification token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		now := time.Now()
		validClaims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}
		validToken, err := service.jwt.CreateVerificationToken(validClaims)
		require.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1", validToken)

		assert.False(t, got)
	})

	t.Run("valid token but different IP", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		now := time.Now()
		validClaims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}
		validToken, err := service.jwt.CreateVerificationToken(validClaims)
		require.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.2", validToken)

		assert.True(t, got)
	})

	t.Run("invalid verification token format", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1", "invalid-jwt-token")

		assert.True(t, got)
	})
}

func TestCaptchaService_VerifyResponse(t *testing.T) {
	t.Run("provider verification success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:         true,
			Provider:        "recaptcha",
			SecretKey:       "test",
			SigningKey:      "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain:    ".example.com",
			SessionDuration: 1 * time.Hour,
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider

		challengeClaims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		challengeToken, err := service.jwt.CreateChallengeToken(challengeClaims)
		require.NoError(t, err)

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "test-token", "192.168.1.1").Return(true, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), challengeToken, req)

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Success)
		assert.Equal(t, "Captcha verified successfully", got.Message)
		assert.NotEmpty(t, got.Token)

		claims, err := service.jwt.VerifyVerificationToken(got.Token)

		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", claims.IP)
		assert.False(t, service.RequiresCaptcha("192.168.1.1", got.Token))
	})

	t.Run("provider verification failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider

		challengeClaims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		challengeToken, err := service.jwt.CreateChallengeToken(challengeClaims)
		require.NoError(t, err)

		req := VerificationRequest{
			Response: "invalid-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "invalid-token", "192.168.1.1").Return(false, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), challengeToken, req)

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "Captcha verification failed", got.Message)
		assert.Empty(t, got.Token)
	})

	t.Run("invalid challenge token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		got, err := service.VerifyResponse(context.Background(), "invalid-token", req)

		assert.Error(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "Invalid or expired challenge token", got.Message)
	})

	t.Run("IP mismatch between challenge and request", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long", CookieDomain: ".example.com"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		challengeClaims := ChallengeClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		challengeToken, err := service.jwt.CreateChallengeToken(challengeClaims)
		require.NoError(t, err)

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.2",
		}

		got, err := service.VerifyResponse(context.Background(), challengeToken, req)

		assert.Error(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "IP mismatch", got.Message)
	})
}

func TestCaptchaService_GetSession(t *testing.T) {
	t.Run("invalid JWT token", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "recaptcha",
			SecretKey:    "test",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
			CallbackURL:  "http://localhost:8081",
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got, gotExists := service.GetSession("invalid-jwt-token")

		assert.False(t, gotExists)
		assert.Nil(t, got)
	})

	t.Run("expired JWT token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain:      ".example.com",
			SiteKey:           "test-site-key",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 1 * time.Millisecond,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = provider

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)
		require.NotNil(t, session)

		time.Sleep(10 * time.Millisecond)

		got, gotExists := service.GetSession(session.ID)

		assert.False(t, gotExists)
		assert.Nil(t, got)
	})

	t.Run("valid JWT token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain:      ".example.com",
			SiteKey:           "test-site-key",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 24 * time.Hour,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = provider

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)
		require.NotNil(t, session)

		got, gotExists := service.GetSession(session.ID)

		require.True(t, gotExists)
		require.NotNil(t, got)
		assert.Equal(t, "192.168.1.1", got.IP)
		assert.Equal(t, "http://example.com", got.OriginalURL)
		assert.Equal(t, "recaptcha", got.Provider)
		assert.Equal(t, "test-site-key", got.SiteKey)
	})
}

func TestCaptchaService_CreateSession(t *testing.T) {
	t.Run("generates challenge data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "turnstile",
			SiteKey:           "test-site-key",
			SecretKey:         "test-secret",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain:      ".example.com",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 5 * time.Minute,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("turnstile").AnyTimes()

		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = provider
		service.nowFunc = func() time.Time { return fixedTime }

		got, err := service.CreateSession("192.168.1.1", "http://example.com/original", "")

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "192.168.1.1", got.IP)
		assert.Equal(t, "http://example.com/original", got.OriginalURL)
		assert.Equal(t, "http://example.com/original", got.RedirectURL)
		assert.Equal(t, fixedTime, got.CreatedAt)
		assert.Equal(t, fixedTime.Add(5*time.Minute), got.ExpiresAt)
		assert.Equal(t, "turnstile", got.Provider)
		assert.Equal(t, "test-site-key", got.SiteKey)
		assert.Equal(t, "http://localhost:8081/captcha", got.CallbackURL)
		assert.NotEmpty(t, got.ID)
		assert.NotEmpty(t, got.ChallengeURL)
	})

	t.Run("returns nil when verification token is valid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "recaptcha",
			SecretKey:    "test",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = provider

		now := time.Now()
		validClaims := VerificationClaims{
			IP: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}
		validToken, err := service.jwt.CreateVerificationToken(validClaims)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "http://example.com", validToken)

		require.NoError(t, err)
		assert.Nil(t, session)
	})

	t.Run("rejects javascript URL", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "turnstile",
			SiteKey:      "test-site-key",
			SecretKey:    "test-secret",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
			CallbackURL:  "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "javascript:alert('xss')", "")

		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("rejects URL without host", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      true,
			Provider:     "turnstile",
			SiteKey:      "test-site-key",
			SecretKey:    "test-secret",
			SigningKey:   "test-signing-key-that-is-at-least-32-bytes-long",
			CookieDomain: ".example.com",
			CallbackURL:  "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "/relative/path", "")

		assert.Error(t, err)
		assert.Nil(t, session)
	})
}
