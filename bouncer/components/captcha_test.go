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
	t.Run("disabled service", func(t *testing.T) {
		service := &CaptchaService{
			Config: config.Captcha{Enabled: false},
		}

		requires := service.RequiresCaptcha("192.168.1.1")

		assert.False(t, requires)
	})

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

		// Add expired entry
		service.Cache.Set("192.168.1.1", time.Now().Add(-1*time.Hour))

		requires := service.RequiresCaptcha("192.168.1.1")

		assert.True(t, requires)
	})

	t.Run("ip in cache and valid", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		// Add valid entry
		service.Cache.Set("192.168.1.1", time.Now().Add(1*time.Hour))

		requires := service.RequiresCaptcha("192.168.1.1")

		assert.False(t, requires)
	})
}

func TestCaptchaService_VerifyResponse(t *testing.T) {
	t.Run("disabled service", func(t *testing.T) {
		service := &CaptchaService{
			Config: config.Captcha{Enabled: false},
		}

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		result, err := service.VerifyResponse(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, "Captcha verification disabled", result.Message)
	})

	t.Run("provider verification success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{
			Enabled:       true,
			Provider:      "recaptcha",
			SecretKey:     "test",
			CacheDuration: 1 * time.Hour,
		}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider // Override with mock

		req := VerificationRequest{
			Response: "test-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "test-token", "192.168.1.1").Return(true, nil).Times(1)

		result, err := service.VerifyResponse(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, "Captcha verified successfully", result.Message)

		// Verify IP was cached
		assert.False(t, service.RequiresCaptcha("192.168.1.1"))
	})

	t.Run("provider verification failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockProvider := mocks.NewMockCaptchaProvider(ctrl)

		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)
		service.Provider = mockProvider

		req := VerificationRequest{
			Response: "invalid-token",
			IP:       "192.168.1.1",
		}

		mockProvider.EXPECT().Verify(gomock.Any(), "invalid-token", "192.168.1.1").Return(false, nil).Times(1)

		result, err := service.VerifyResponse(context.Background(), req)

		assert.NoError(t, err)
		assert.False(t, result.Success)
		assert.Equal(t, "Captcha verification failed", result.Message)
	})
}

func TestCaptchaService_CreateSession(t *testing.T) {
	t.Run("successful session creation", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		sessionID, err := service.CreateSession("192.168.1.1", "http://example.com/test")

		assert.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Len(t, sessionID, 64) // hex-encoded 32 bytes

		// Verify session was stored
		session, exists := service.GetSession(sessionID)
		assert.True(t, exists)
		assert.Equal(t, "192.168.1.1", session.IP)
		assert.Equal(t, "http://example.com/test", session.OriginalURL)
		assert.False(t, session.Verified)
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
			Verified:    false,
		}
		service.SessionCache.Set("expired-session", expiredSession)

		session, exists := service.GetSession("expired-session")

		assert.False(t, exists)
		assert.Nil(t, session)
	})

	t.Run("valid session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		// Create valid session
		validSession := CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
			CreatedAt:   time.Now(),
			Verified:    false,
		}
		service.SessionCache.Set("valid-session", validSession)

		session, exists := service.GetSession("valid-session")

		assert.True(t, exists)
		assert.NotNil(t, session)
		assert.Equal(t, "192.168.1.1", session.IP)
		assert.Equal(t, "http://example.com", session.OriginalURL)
	})
}

func TestCaptchaService_MarkSessionVerified(t *testing.T) {
	t.Run("non-existent session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		success := service.MarkSessionVerified("non-existent")

		assert.False(t, success)
	})

	t.Run("valid session", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		sessionID, err := service.CreateSession("192.168.1.1", "http://example.com")
		assert.NoError(t, err)

		success := service.MarkSessionVerified(sessionID)

		assert.True(t, success)

		// Verify session is marked as verified
		session, exists := service.GetSession(sessionID)
		assert.True(t, exists)
		assert.True(t, session.Verified)
	})
}

func TestCaptchaService_GetVerifiedSessionForIP(t *testing.T) {
	t.Run("ip not in cache", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		session := service.GetVerifiedSessionForIP("192.168.1.1")

		assert.Nil(t, session)
	})

	t.Run("ip in cache", func(t *testing.T) {
		cfg := config.Captcha{Enabled: true, Provider: "recaptcha", SecretKey: "test"}
		service, err := NewCaptchaService(cfg, http.DefaultClient)
		assert.NoError(t, err)

		// Add IP to cache
		service.Cache.Set("192.168.1.1", time.Now().Add(1*time.Hour))

		session := service.GetVerifiedSessionForIP("192.168.1.1")

		assert.NotNil(t, session)
		assert.Equal(t, "192.168.1.1", session.IP)
		assert.True(t, session.Verified)
	})
}

func TestRenderCaptchaTemplate(t *testing.T) {
	t.Run("recaptcha template", func(t *testing.T) {
		html, err := RenderCaptchaTemplate("recaptcha", "site-key", "http://localhost/callback", "http://localhost/redirect", "session-123")

		assert.NoError(t, err)
		assert.Contains(t, html, "site-key")
		assert.Contains(t, html, "http://localhost/callback")
		assert.Contains(t, html, "session-123")
		assert.Contains(t, html, "recaptcha")
		assert.Contains(t, html, "www.google.com/recaptcha/api.js")
	})

	t.Run("turnstile template", func(t *testing.T) {
		html, err := RenderCaptchaTemplate("turnstile", "site-key", "http://localhost/callback", "http://localhost/redirect", "session-123")

		assert.NoError(t, err)
		assert.Contains(t, html, "site-key")
		assert.Contains(t, html, "http://localhost/callback")
		assert.Contains(t, html, "session-123")
		assert.Contains(t, html, "turnstile")
		assert.Contains(t, html, "challenges.cloudflare.com")
	})
}
