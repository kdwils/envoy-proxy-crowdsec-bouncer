package components

import (
	"context"
	"net/http"
	"testing"
	"time"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewCaptchaService(t *testing.T) {
	t.Run("disabled captcha", func(t *testing.T) {
		cfg := config.Captcha{Enabled: false}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, service)
		assert.False(t, service.Config.Enabled)
		assert.Nil(t, service.Provider)
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

		assert.NoError(t, err)
		requires := service.RequiresCaptcha("192.168.1.1")

		assert.True(t, requires)
	})

	t.Run("ip in cache but expired", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		service.VerifiedCache.Set("192.168.1.1", time.Now().Add(-1*time.Hour))

		requires := service.RequiresCaptcha("192.168.1.1")

		assert.True(t, requires)
	})

	t.Run("ip in cache and valid", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		service.VerifiedCache.Set("192.168.1.1", time.Now().Add(1*time.Hour))

		requires := service.RequiresCaptcha("192.168.1.1")

		assert.False(t, requires)
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

		service.ChallengeSessionCache.Set("test", CaptchaSession{})

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "test-token", "192.168.1.1").Return(true, nil).Times(1)

		result, err := service.VerifyResponse(context.Background(), "test", req)

		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, "Captcha verified successfully", result.Message)
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

		service.ChallengeSessionCache.Set("test", CaptchaSession{})

		req := VerificationRequest{
			Response: "invalid-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "invalid-token", "192.168.1.1").Return(false, nil).Times(1)

		result, err := service.VerifyResponse(context.Background(), "test", req)

		assert.NoError(t, err)
		assert.False(t, result.Success)
		assert.Equal(t, "Captcha verification failed", result.Message)
		_, ok := service.GetSession("test")
		assert.False(t, ok)
	})
}

func TestCaptchaService_GetSession(t *testing.T) {
	t.Run("non-existent session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		session, exists := service.GetSession("non-existent")

		assert.False(t, exists)
		assert.Nil(t, session)
	})

	t.Run("expired session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		// Create expired session
		expiredSession := CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			CreatedAt:   time.Now().Add(-15 * time.Minute), // Expired
		}
		service.ChallengeSessionCache.Set("expired-session", expiredSession)

		session, exists := service.GetSession("expired-session")

		assert.False(t, exists)
		assert.Nil(t, session)
	})

	t.Run("valid session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		now := time.Now()

		validSession := CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Hour * 1),
		}

		service.ChallengeSessionCache.Set("valid-session", validSession)

		session, exists := service.GetSession("valid-session")

		assert.True(t, exists)
		assert.NotNil(t, session)
		assert.Equal(t, "192.168.1.1", session.IP)
		assert.Equal(t, "http://example.com", session.OriginalURL)
	})
}

func TestCaptchaService_CreateSession(t *testing.T) {
	t.Run("generates challenge data", func(t *testing.T) {
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
		provider.EXPECT().GetProviderName().Return("turnstile")

		service := &CaptchaService{
			Config:                cfg,
			Provider:              provider,
			VerifiedCache:         cache.New(cache.WithCleanupInterval[time.Time](time.Minute)),
			ChallengeSessionCache: cache.New(cache.WithCleanupInterval[CaptchaSession](time.Minute)),
		}

		session, err := service.CreateSession("192.168.1.1", "http://example.com/original")

		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, "turnstile", session.Provider)
		assert.Equal(t, "test-site-key", session.SiteKey)
		assert.Equal(t, "http://localhost:8081/captcha", session.CallbackURL)
		assert.Equal(t, "http://example.com/original", session.RedirectURL)
		assert.NotEmpty(t, session.ID)
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
