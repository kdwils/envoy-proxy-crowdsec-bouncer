package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetViper(t *testing.T) {
	t.Run("config file is set when provided", func(t *testing.T) {
		assert.Equal(t, "testdata/config.yaml", GetViper("testdata/config.yaml").ConfigFileUsed())
	})

	t.Run("config file is unset when empty", func(t *testing.T) {
		assert.Equal(t, "", GetViper("").ConfigFileUsed())
	})

	t.Run("returns default values", func(t *testing.T) {
		got, err := New(GetViper(""))
		require.NoError(t, err)

		want := Config{
			Server: Server{
				GRPCPort: 8080,
				HTTPPort: 8081,
				LogLevel: "info",
			},
			Bouncer: Bouncer{
				Enabled:         true,
				Metrics:         false,
				TickerInterval:  "10s",
				MetricsInterval: 10 * time.Minute,
				ApiKey:          "",
				LAPIURL:         "",
				BanStatusCode:   403,
				TLS: BouncerTLS{
					Enabled:            false,
					CertPath:           "",
					KeyPath:            "",
					CAPath:             "",
					InsecureSkipVerify: false,
				},
			},
			WAF: WAF{
				Enabled:     false,
				AppSecURL:   "",
				ApiKey:      "",
				HTTPTimeout: 5 * time.Second,
				FailOpen:    false,
			},
			Captcha: Captcha{
				Enabled:                          false,
				Provider:                         "",
				SiteKey:                          "",
				SecretKey:                        "",
				SigningKey:                       "",
				CallbackURL:                      "",
				CookieDomain:                     "",
				CookieName:                       "session",
				SecureCookie:                     true,
				Timeout:                          10 * time.Second,
				ChallengeDuration:                5 * time.Minute,
				SessionDuration:                  15 * time.Minute,
				DisableChallengeReplayProtection: false,
			},
			Webhook: Webhook{
				Subscriptions: nil,
				SigningKey:    "",
				Timeout:       5 * time.Second,
				BufferSize:    100,
			},
			Prometheus: Prometheus{
				Enabled: false,
				Port:    9090,
			},
			TrustedProxies:  []string{},
			TrustedIPHeader: "",
			ExemptIPs:       []string{},
			Templates: Templates{
				DeniedTemplatePath:     "",
				DeniedTemplateHeaders:  "text/html; charset=utf-8",
				ShowDeniedPage:         true,
				CaptchaTemplatePath:    "",
				CaptchaTemplateHeaders: "text/html; charset=utf-8",
			},
			HTTP: HTTP{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
		assert.Equal(t, want, got)
	})
}
