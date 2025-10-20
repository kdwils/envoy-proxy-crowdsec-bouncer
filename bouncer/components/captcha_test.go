package components

import (
	"context"
	"net/http"
	"testing"
	"time"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewCaptchaService(t *testing.T) {
	t.Run("disabled captcha", func(t *testing.T) {
		cfg := config.Captcha{Enabled: false}

		got, err := NewCaptchaService(cfg, http.DefaultClient)

		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.Equal(t, cfg, got.Config)
		assert.Nil(t, got.Provider)
		assert.NotNil(t, got.VerifiedCache)
		assert.NotNil(t, got.ChallengeSessionCache)
		assert.Equal(t, 10*time.Second, got.RequestTimeout)
		assert.NotNil(t, got.generateToken)
		assert.NotNil(t, got.nowFunc)
	})

	t.Run("recaptcha provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:   true,
			Provider:  "recaptcha",
			SecretKey: "test-secret",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, service)
		assert.True(t, service.Config.Enabled)
		assert.NotNil(t, service.Provider)
		assert.Equal(t, "recaptcha", service.Provider.GetProviderName())
	})

	t.Run("turnstile provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:   true,
			Provider:  "turnstile",
			SecretKey: "test-secret",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, service)
		assert.True(t, service.Config.Enabled)
		assert.NotNil(t, service.Provider)
		assert.Equal(t, "turnstile", service.Provider.GetProviderName())
	})

	t.Run("unsupported provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:  true,
			Provider: "unsupported",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)

		assert.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "unsupported captcha provider")
	})
}

func TestCaptchaService_RequiresCaptcha(t *testing.T) {

	t.Run("ip not in cache", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1")

		assert.Equal(t, true, got)
	})

	t.Run("ip in cache but expired", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		service.VerifiedCache.Set("192.168.1.1", time.Now().Add(-1*time.Hour))

		got := service.RequiresCaptcha("192.168.1.1")

		assert.Equal(t, true, got)
	})

	t.Run("ip in cache and valid", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		service.VerifiedCache.Set("192.168.1.1", time.Now().Add(1*time.Hour))

		got := service.RequiresCaptcha("192.168.1.1")

		assert.Equal(t, false, got)
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
			SessionDuration: 1 * time.Hour,
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider

		service.ChallengeSessionCache.Set("test", CaptchaSession{
			IP:          "192.168.1.1",
			ID:          "test",
			OriginalURL: "http://example.com/test",
			RedirectURL: "http://example.com/test",
		})

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "test-token", "192.168.1.1").Return(true, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), "test", req)

		assert.NoError(t, err)

		want := &VerificationResult{
			Success: true,
			Message: "Captcha verified successfully",
		}

		assert.Equal(t, want, got)
		assert.False(t, service.RequiresCaptcha("192.168.1.1"))
		_, ok := service.GetSession("test")
		assert.False(t, ok)
	})

	t.Run("provider verification failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider

		service.ChallengeSessionCache.Set("test", CaptchaSession{
			IP:          "192.168.1.1",
			ID:          "test",
			OriginalURL: "http://example.com/test",
			RedirectURL: "http://example.com/test",
		})

		req := VerificationRequest{
			Response: "invalid-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "invalid-token", "192.168.1.1").Return(false, nil).Times(1)

		got, err := service.VerifyResponse(context.Background(), "test", req)

		assert.NoError(t, err)

		want := &VerificationResult{
			Success: false,
			Message: "Captcha verification failed",
		}

		assert.Equal(t, want, got)
		_, ok := service.GetSession("test")
		assert.False(t, ok)
	})
}

func TestCaptchaService_GetSession(t *testing.T) {
	t.Run("non-existent session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		got, gotExists := service.GetSession("non-existent")

		assert.Equal(t, false, gotExists)
		assert.Nil(t, got)
	})

	t.Run("expired session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		now := time.Now()
		expiredSession := CaptchaSession{
			IP:          "192.168.1.1",
			ID:          "expired-session",
			OriginalURL: "http://example.com",
			RedirectURL: "http://example.com",
			CreatedAt:   now.Add(-15 * time.Minute),
			ExpiresAt:   now.Add(-10 * time.Minute),
		}
		service.ChallengeSessionCache.Set("expired-session", expiredSession)

		got, gotExists := service.GetSession("expired-session")

		assert.Equal(t, false, gotExists)
		assert.Nil(t, got)
	})

	t.Run("valid session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		now := time.Now()

		validSession := CaptchaSession{
			IP:           "192.168.1.1",
			ID:           "valid-session",
			OriginalURL:  "http://example.com",
			RedirectURL:  "http://example.com",
			CreatedAt:    now,
			ExpiresAt:    now.Add(time.Hour * 1),
			Provider:     "recaptcha",
			SiteKey:      "test-site-key",
			CallbackURL:  "http://localhost:8081/captcha",
			ChallengeURL: "http://localhost:8081/captcha/challenge?session=valid-session",
			CSRFToken:    "csrf-token",
		}

		service.ChallengeSessionCache.Set("valid-session", validSession)

		got, gotExists := service.GetSession("valid-session")

		want := &CaptchaSession{
			IP:           "192.168.1.1",
			ID:           "valid-session",
			OriginalURL:  "http://example.com",
			RedirectURL:  "http://example.com",
			CreatedAt:    now,
			ExpiresAt:    now.Add(time.Hour * 1),
			Provider:     "recaptcha",
			SiteKey:      "test-site-key",
			CallbackURL:  "http://localhost:8081/captcha",
			ChallengeURL: "http://localhost:8081/captcha/challenge?session=valid-session",
			CSRFToken:    "csrf-token",
		}

		assert.Equal(t, true, gotExists)
		assert.Equal(t, want, got)
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
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 5 * time.Minute,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("turnstile")

		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		tokenCounter := 0
		tokens := []string{"test-session-id", "test-csrf-token"}

		service := &CaptchaService{
			Config:                cfg,
			Provider:              provider,
			VerifiedCache:         cache.New(cache.WithCleanupInterval[time.Time](time.Minute)),
			ChallengeSessionCache: cache.New(cache.WithCleanupInterval[CaptchaSession](time.Minute)),
			generateToken: func() (string, error) {
				token := tokens[tokenCounter]
				tokenCounter++
				return token, nil
			},
			nowFunc: func() time.Time {
				return fixedTime
			},
		}

		got, err := service.CreateSession("192.168.1.1", "http://example.com/original")

		assert.NoError(t, err)

		want := &CaptchaSession{
			IP:           "192.168.1.1",
			ID:           "test-session-id",
			OriginalURL:  "http://example.com/original",
			RedirectURL:  "http://example.com/original",
			CreatedAt:    fixedTime,
			ExpiresAt:    fixedTime.Add(5 * time.Minute),
			Provider:     "turnstile",
			SiteKey:      "test-site-key",
			CallbackURL:  "http://localhost:8081/captcha",
			ChallengeURL: "http://localhost:8081/captcha/challenge?session=test-session-id",
			CSRFToken:    "test-csrf-token",
		}

		assert.Equal(t, want, got)
	})

	t.Run("rejects javascript URL", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			CallbackURL: "http://localhost:8081",
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)

		service := &CaptchaService{
			Config:                cfg,
			Provider:              provider,
			VerifiedCache:         cache.New(cache.WithCleanupInterval[time.Time](time.Minute)),
			ChallengeSessionCache: cache.New(cache.WithCleanupInterval[CaptchaSession](time.Minute)),
		}

		session, err := service.CreateSession("192.168.1.1", "javascript:alert('xss')")

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "invalid redirect URL")
	})

	t.Run("rejects URL without host", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			CallbackURL: "http://localhost:8081",
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)

		service := &CaptchaService{
			Config:                cfg,
			Provider:              provider,
			VerifiedCache:         cache.New(cache.WithCleanupInterval[time.Time](time.Minute)),
			ChallengeSessionCache: cache.New(cache.WithCleanupInterval[CaptchaSession](time.Minute)),
		}

		session, err := service.CreateSession("192.168.1.1", "/relative/path")

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "invalid redirect URL")
	})
}
