package components

import (
	"context"
	"net/http"
	"testing"
	"time"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
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
		assert.NotNil(t, got.jwt)
		assert.Equal(t, 10*time.Second, got.RequestTimeout)
		assert.NotNil(t, got.generateToken)
		assert.NotNil(t, got.nowFunc)
	})

	t.Run("recaptcha provider", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:    true,
			Provider:   "recaptcha",
			SecretKey:  "test-secret",
			SigningKey: "test-signing-key",
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
			Enabled:    true,
			Provider:   "turnstile",
			SecretKey:  "test-secret",
			SigningKey: "test-signing-key",
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
			Enabled:    true,
			Provider:   "unsupported",
			SigningKey: "test-signing-key",
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

	t.Run("ip not in cache", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		got := service.RequiresCaptcha("192.168.1.1")

		assert.Equal(t, true, got)
	})

	t.Run("ip in cache but expired", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		service.VerifiedCache.Set("192.168.1.1", time.Now().Add(-1*time.Hour))

		got := service.RequiresCaptcha("192.168.1.1")

		assert.Equal(t, true, got)
	})

	t.Run("ip in cache and valid", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key"}
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
			SigningKey:      "test-signing-key",
			SessionDuration: 1 * time.Hour,
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider

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
	})

	t.Run("provider verification failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test", SigningKey: "test-signing-key"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider

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
	})
}

func TestCaptchaService_GetSession(t *testing.T) {
	t.Run("invalid JWT token", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "recaptcha",
			SecretKey:   "test",
			SigningKey:  "test-signing-key",
			CallbackURL: "http://localhost:8081",
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

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
			SigningKey:        "test-signing-key",
			SiteKey:           "test-site-key",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 1 * time.Millisecond,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("recaptcha")

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = provider

		session, err := service.CreateSession("192.168.1.1", "http://example.com")
		assert.NoError(t, err)
		assert.NotNil(t, session)

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
			SigningKey:        "test-signing-key",
			SiteKey:           "test-site-key",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 24 * time.Hour,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("recaptcha")

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = provider

		session, err := service.CreateSession("192.168.1.1", "http://example.com")
		assert.NoError(t, err)
		assert.NotNil(t, session)

		got, gotExists := service.GetSession(session.ID)

		assert.True(t, gotExists)
		assert.NotNil(t, got)
		assert.Equal(t, "192.168.1.1", got.IP)
		assert.Equal(t, "http://example.com", got.OriginalURL)
		assert.Equal(t, "recaptcha", got.Provider)
		assert.Equal(t, "test-site-key", got.SiteKey)
		assert.Equal(t, session.CSRFToken, got.CSRFToken)
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
			SigningKey:        "test-signing-key",
			CallbackURL:       "http://localhost:8081",
			ChallengeDuration: 5 * time.Minute,
		}

		provider := mocks.NewMockCaptchaProvider(ctrl)
		provider.EXPECT().GetProviderName().Return("turnstile")

		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = provider

		service.generateToken = func() (string, error) {
			return "test-csrf-token", nil
		}
		service.nowFunc = func() time.Time {
			return fixedTime
		}

		got, err := service.CreateSession("192.168.1.1", "http://example.com/original")

		assert.NoError(t, err)
		assert.NotNil(t, got)
		assert.Equal(t, "192.168.1.1", got.IP)
		assert.Equal(t, "http://example.com/original", got.OriginalURL)
		assert.Equal(t, "http://example.com/original", got.RedirectURL)
		assert.Equal(t, fixedTime, got.CreatedAt)
		assert.Equal(t, fixedTime.Add(5*time.Minute), got.ExpiresAt)
		assert.Equal(t, "turnstile", got.Provider)
		assert.Equal(t, "test-site-key", got.SiteKey)
		assert.Equal(t, "http://localhost:8081/captcha", got.CallbackURL)
		assert.Equal(t, "test-csrf-token", got.CSRFToken)
		assert.NotEmpty(t, got.ID)
		assert.NotEmpty(t, got.ChallengeURL)
	})

	t.Run("rejects javascript URL", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			SigningKey:  "test-signing-key",
			CallbackURL: "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "javascript:alert('xss')")

		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("rejects URL without host", func(t *testing.T) {
		cfg := config.Captcha{
			Enabled:     true,
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			SecretKey:   "test-secret",
			SigningKey:  "test-signing-key",
			CallbackURL: "http://localhost:8081",
		}

		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		session, err := service.CreateSession("192.168.1.1", "/relative/path")

		assert.Error(t, err)
		assert.Nil(t, session)
	})
}
