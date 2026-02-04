package components

import (
	"context"
	"net/http"
	"testing"
	"time"

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

		token, claims, err := manager.CreateChallengeToken("http://example.com", "192.168.1.1", now, 5*time.Minute)

		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotNil(t, claims)
		assert.NotEmpty(t, claims.IPHash)
		assert.Equal(t, "http://example.com", claims.OriginalURL)
		assert.NotEmpty(t, claims.ID)

		verifiedClaims, err := manager.CheckChallengeToken(token)

		require.NoError(t, err)
		require.NotNil(t, verifiedClaims)
		assert.Equal(t, claims.IPHash, verifiedClaims.IPHash)
		assert.Equal(t, "http://example.com", verifiedClaims.OriginalURL)
	})

	t.Run("verifies IP hash correctly", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		_, claims, err := manager.CreateChallengeToken("http://example.com", "192.168.1.1", now, 5*time.Minute)
		require.NoError(t, err)

		assert.True(t, manager.VerifyIPHash(claims, "192.168.1.1"))
		assert.False(t, manager.VerifyIPHash(claims, "192.168.1.2"))
	})

	t.Run("rejects expired challenge token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now().Add(-2 * time.Hour)

		token, _, err := manager.CreateChallengeToken("http://example.com", "192.168.1.1", now, 1*time.Hour)
		require.NoError(t, err)

		verifiedClaims, err := manager.CheckChallengeToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects invalid challenge token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")

		verifiedClaims, err := manager.CheckChallengeToken("invalid-token")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects challenge token with wrong signing key", func(t *testing.T) {
		manager1 := NewJWTManager("key-1-that-is-at-least-32-bytes-long")
		manager2 := NewJWTManager("key-2-that-is-at-least-32-bytes-long")
		now := time.Now()

		token, _, err := manager1.CreateChallengeToken("http://example.com", "192.168.1.1", now, 5*time.Minute)
		require.NoError(t, err)

		verifiedClaims, err := manager2.CheckChallengeToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})
}

func TestJWTManager_SessionToken(t *testing.T) {
	t.Run("creates and verifies session token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now()

		token, err := manager.CreateSessionToken("test-session-id", now, 1*time.Hour)

		require.NoError(t, err)
		require.NotEmpty(t, token)

		verifiedClaims, err := manager.VerifySessionToken(token)

		require.NoError(t, err)
		require.NotNil(t, verifiedClaims)
		assert.Equal(t, "test-session-id", verifiedClaims.SID)
	})

	t.Run("rejects expired session token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")
		now := time.Now().Add(-2 * time.Hour)

		token, err := manager.CreateSessionToken("test-session-id", now, 1*time.Hour)
		require.NoError(t, err)

		verifiedClaims, err := manager.VerifySessionToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects invalid session token", func(t *testing.T) {
		manager := NewJWTManager("test-signing-key-that-is-at-least-32-bytes-long")

		verifiedClaims, err := manager.VerifySessionToken("invalid-token")

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
		assert.NotNil(t, got.challengeCache)
	})

	t.Run("recaptcha provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:    true,
			Provider:   "recaptcha",
			SecretKey:  "test-secret",
			SigningKey: "test-signing-key-that-is-at-least-32-bytes-long",
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
			Enabled:    true,
			Provider:   "turnstile",
			SecretKey:  "test-secret",
			SigningKey: "test-signing-key-that-is-at-least-32-bytes-long",
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
	t.Run("no session token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got := service.RequiresCaptcha("")

		assert.True(t, got)
	})

	t.Run("expired session token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		now := time.Now().Add(-2 * time.Hour)
		expiredToken, err := service.jwt.CreateSessionToken("test-session", now, 1*time.Hour)
		require.NoError(t, err)

		got := service.RequiresCaptcha(expiredToken)

		assert.True(t, got)
	})

	t.Run("valid session token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		now := time.Now()
		validToken, err := service.jwt.CreateSessionToken("test-session", now, 1*time.Hour)
		require.NoError(t, err)

		got := service.RequiresCaptcha(validToken)

		assert.False(t, got)
	})

	t.Run("invalid session token format", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got := service.RequiresCaptcha("invalid-jwt-token")

		assert.True(t, got)
	})
}

func TestCaptchaService_VerifyResponse(t *testing.T) {
	t.Run("provider verification success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			SessionDuration:   1 * time.Hour,
			ChallengeDuration: 5 * time.Minute,
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider
		mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)
		require.NotNil(t, session)

		mockProvider.EXPECT().Verify(gomock.Any(), "test-captcha-response", "192.168.1.1").Return(true, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), "192.168.1.1", session.ID, "test-captcha-response")

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Success)
		assert.Equal(t, "Captcha verified successfully", got.Message)
		assert.NotEmpty(t, got.Token)

		claims, err := service.jwt.VerifySessionToken(got.Token)

		require.NoError(t, err)
		assert.NotEmpty(t, claims.SID)
		assert.False(t, service.RequiresCaptcha(got.Token))
	})

	t.Run("provider verification failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			ChallengeDuration: 5 * time.Minute,
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider
		mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)

		mockProvider.EXPECT().Verify(gomock.Any(), "invalid-token", "192.168.1.1").Return(false, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), "192.168.1.1", session.ID, "invalid-token")

		assert.ErrorIs(t, err, ErrFailedChallenge)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "Captcha verification failed", got.Message)
		assert.Empty(t, got.Token)
	})

	t.Run("invalid challenge token", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key-that-is-at-least-32-bytes-long"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		got, err := service.VerifyResponse(context.Background(), "192.168.1.1", "invalid-token", "test-response")

		assert.Error(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "Invalid or expired challenge token", got.Message)
	})

	t.Run("IP mismatch between challenge and request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			ChallengeDuration: 5 * time.Minute,
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider
		mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)

		got, err := service.VerifyResponse(context.Background(), "192.168.1.2", session.ID, "test-response")

		assert.Error(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Success)
		assert.Equal(t, "IP mismatch", got.Message)
	})

	t.Run("challenge token replay rejected", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:           true,
			Provider:          "recaptcha",
			SecretKey:         "test",
			SigningKey:        "test-signing-key-that-is-at-least-32-bytes-long",
			SessionDuration:   1 * time.Hour,
			ChallengeDuration: 5 * time.Minute,
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = mockProvider
		mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		session, err := service.CreateSession("192.168.1.1", "http://example.com", "")
		require.NoError(t, err)

		mockProvider.EXPECT().Verify(gomock.Any(), "test-response", "192.168.1.1").Return(true, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), "192.168.1.1", session.ID, "test-response")
		require.NoError(t, err)
		assert.True(t, got.Success)

		got2, err := service.VerifyResponse(context.Background(), "192.168.1.1", session.ID, "test-response")
		assert.Error(t, err)
		assert.False(t, got2.Success)
		assert.Equal(t, "Challenge already used or expired", got2.Message)
	})
}

func TestCaptchaService_GetSession(t *testing.T) {
	t.Run("invalid JWT token", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "recaptcha",
			SecretKey:   "test",
			SigningKey:  "test-signing-key-that-is-at-least-32-bytes-long",
			CallbackURL: "http://localhost:8081",
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

	t.Run("returns nil when session token is valid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:    true,
			Provider:   "recaptcha",
			SecretKey:  "test",
			SigningKey: "test-signing-key-that-is-at-least-32-bytes-long",
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)
		service.Provider = provider

		now := time.Now()
		validToken, err := service.jwt.CreateSessionToken("test-session", now, 1*time.Hour)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "http://example.com", validToken)

		require.NoError(t, err)
		assert.Nil(t, session)
	})

	t.Run("rejects javascript URL", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			SigningKey:  "test-signing-key-that-is-at-least-32-bytes-long",
			CallbackURL: "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "javascript:alert('xss')", "")

		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("rejects URL without host", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			SigningKey:  "test-signing-key-that-is-at-least-32-bytes-long",
			CallbackURL: "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "/relative/path", "")

		assert.Error(t, err)
		assert.Nil(t, session)
	})
}

func TestCaptchaService_CookieName(t *testing.T) {
	t.Run("returns configured cookie name", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:    false,
			CookieName: "my-custom-cookie",
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		assert.Equal(t, "my-custom-cookie", service.CookieName())
	})

	t.Run("returns session for non-secure cookie", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:      false,
			SecureCookie: false,
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		require.NoError(t, err)

		assert.Equal(t, "session", service.CookieName())
	})
}
