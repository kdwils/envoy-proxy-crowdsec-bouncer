package config

import (
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBouncer_ValidateAuth(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Bouncer
		wantErr string
	}{
		{
			name:    "no auth provided",
			cfg:     Bouncer{},
			wantErr: "api key or certificate auth required",
		},
		{
			name: "api key and tls both enabled",
			cfg: Bouncer{
				ApiKey: "test-key",
				TLS:    BouncerTLS{Enabled: true, CertPath: "/path/to/cert", KeyPath: "/path/to/key"},
			},
			wantErr: "cannot use both API key and certificate auth",
		},
		{
			name:    "only api key provided",
			cfg:     Bouncer{ApiKey: "test-key"},
			wantErr: "",
		},
		{
			name: "tls enabled with cert and key paths",
			cfg: Bouncer{
				TLS: BouncerTLS{Enabled: true, CertPath: "/path/cert", KeyPath: "/path/key"},
			},
			wantErr: "",
		},
		{
			name: "tls enabled but cert path missing",
			cfg: Bouncer{
				TLS: BouncerTLS{Enabled: true, KeyPath: "/path/to/key"},
			},
			wantErr: "certificate auth requires both certPath and keyPath",
		},
		{
			name: "tls enabled but key path missing",
			cfg: Bouncer{
				TLS: BouncerTLS{Enabled: true, CertPath: "/path/to/cert"},
			},
			wantErr: "certificate auth requires both certPath and keyPath",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ValidateAuth()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error())
		})
	}
}

func TestNew(t *testing.T) {
	t.Run("nil viper returns error", func(t *testing.T) {
		c, err := New(nil)
		assert.Error(t, err)
		assert.Equal(t, "viper not initialized", err.Error())
		assert.Empty(t, c)
	})

	t.Run("valid viper config", func(t *testing.T) {
		v := viper.New()
		v.Set("server.grpcPort", 8080)
		v.Set("server.httpPort", 8081)
		v.Set("server.logLevel", "debug")
		v.Set("bouncer.apiKey", "test-key")
		v.Set("bouncer.lapiURL", "http://test.com")
		v.Set("trustedProxies", []string{"127.0.0.1"})
		v.Set("exemptIPs", []string{"10.0.0.0/8"})
		v.Set("bouncer.metrics", true)
		v.Set("bouncer.tickerInterval", "30s")
		v.Set("waf.enabled", true)
		v.Set("waf.apiKey", "test-key")
		v.Set("waf.appSecURL", "http://test.com")
		v.Set("waf.httpTimeout", "1s")
		v.Set("waf.failOpen", true)
		v.Set("http.maxIdleConns", 42)
		v.Set("http.maxIdleConnsPerHost", 7)
		v.Set("http.idleConnTimeout", "5s")
		v.Set("http.tlsHandshakeTimeout", "2s")

		c, err := New(v)
		assert.NoError(t, err)

		want := Config{
			Server: Server{
				GRPCPort: 8080,
				HTTPPort: 8081,
				LogLevel: "debug",
			},
			Bouncer: Bouncer{
				Enabled:         false,
				Metrics:         true,
				TickerInterval:  "30s",
				MetricsInterval: 0,
				ApiKey:          "test-key",
				LAPIURL:         "http://test.com",
				BanStatusCode:   0,
				TLS: BouncerTLS{
					Enabled:            false,
					CertPath:           "",
					KeyPath:            "",
					CAPath:             "",
					InsecureSkipVerify: false,
				},
			},
			WAF: WAF{
				Enabled:     true,
				AppSecURL:   "http://test.com",
				ApiKey:      "test-key",
				HTTPTimeout: time.Second,
				FailOpen:    true,
			},
			Captcha: Captcha{
				Enabled:                          false,
				Provider:                         "",
				SiteKey:                          "",
				SecretKey:                        "",
				SigningKey:                       "",
				CallbackURL:                      "",
				CookieDomain:                     "",
				CookieName:                       "",
				SecureCookie:                     false,
				Timeout:                          0,
				ChallengeDuration:                0,
				SessionDuration:                  0,
				DisableChallengeReplayProtection: false,
			},
			Webhook: Webhook{
				Subscriptions: nil,
				SigningKey:    "",
				Timeout:       0,
				BufferSize:    0,
			},
			Prometheus: Prometheus{
				Enabled: false,
				Port:    0,
			},
			TrustedProxies:  []string{"127.0.0.1"},
			TrustedIPHeader: "",
			ExemptIPs:       []string{"10.0.0.0/8"},
			Templates: Templates{
				DeniedTemplatePath:     "",
				DeniedTemplateHeaders:  "",
				ShowDeniedPage:         false,
				CaptchaTemplatePath:    "",
				CaptchaTemplateHeaders: "",
			},
			HTTP: HTTP{
				MaxIdleConns:        42,
				MaxIdleConnsPerHost: 7,
				IdleConnTimeout:     5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
			},
		}
		assert.Equal(t, want, c)
	})
}

func TestHTTP_NewClient(t *testing.T) {
	t.Run("applies configured transport settings", func(t *testing.T) {
		cfg := HTTP{
			MaxIdleConns:        42,
			MaxIdleConnsPerHost: 7,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: 2 * time.Second,
		}

		client := cfg.NewClient()
		require.NotNil(t, client)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, 42, transport.MaxIdleConns)
		assert.Equal(t, 7, transport.MaxIdleConnsPerHost)
		assert.Equal(t, 5*time.Second, transport.IdleConnTimeout)
		assert.Equal(t, 2*time.Second, transport.TLSHandshakeTimeout)
	})

	t.Run("unset fields use Go transport semantics", func(t *testing.T) {
		client := HTTP{}.NewClient()
		require.NotNil(t, client)

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Zero(t, transport.MaxIdleConns)
		assert.Zero(t, transport.MaxIdleConnsPerHost)
		assert.Zero(t, transport.IdleConnTimeout)
		assert.Zero(t, transport.TLSHandshakeTimeout)
	})

	t.Run("partially configured settings use Go semantics for the rest", func(t *testing.T) {
		cfg := HTTP{MaxIdleConns: 500}

		client := cfg.NewClient()

		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, 500, transport.MaxIdleConns)
		assert.Zero(t, transport.MaxIdleConnsPerHost)
		assert.Zero(t, transport.IdleConnTimeout)
		assert.Zero(t, transport.TLSHandshakeTimeout)
	})
}

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
				ShowDeniedPage:         false,
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
