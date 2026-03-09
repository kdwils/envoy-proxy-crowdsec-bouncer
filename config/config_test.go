package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBouncer_ValidateAuth(t *testing.T) {
	t.Run("returns error when no auth provided", func(t *testing.T) {
		cfg := Bouncer{}
		err := cfg.ValidateAuth()
		require.Error(t, err)
		assert.Equal(t, "api key or certificate auth required", err.Error())
	})

	t.Run("returns error when api key and tls both enabled", func(t *testing.T) {
		cfg := Bouncer{
			ApiKey: "test-key",
			TLS:    BouncerTLS{Enabled: true, CertPath: "/path/to/cert", KeyPath: "/path/to/key"},
		}
		err := cfg.ValidateAuth()
		require.Error(t, err)
		assert.Equal(t, "cannot use both API key and certificate auth", err.Error())
	})

	t.Run("returns nil when only api key provided", func(t *testing.T) {
		cfg := Bouncer{ApiKey: "test-key"}
		err := cfg.ValidateAuth()
		assert.Nil(t, err)
	})

	t.Run("returns nil when api key provided and tls disabled with default paths", func(t *testing.T) {
		cfg := Bouncer{
			ApiKey: "test-key",
			TLS:    BouncerTLS{Enabled: false, CertPath: "/app/tls/tls.crt", KeyPath: "/app/tls/tls.key"},
		}
		err := cfg.ValidateAuth()
		assert.Nil(t, err)
	})

	t.Run("returns nil when tls enabled with cert and key paths", func(t *testing.T) {
		cfg := Bouncer{
			TLS: BouncerTLS{Enabled: true, CertPath: "/path/cert", KeyPath: "/path/key"},
		}
		err := cfg.ValidateAuth()
		assert.Nil(t, err)
	})

	t.Run("returns error when tls enabled but cert path missing", func(t *testing.T) {
		cfg := Bouncer{
			TLS: BouncerTLS{Enabled: true, KeyPath: "/path/to/key"},
		}
		err := cfg.ValidateAuth()
		require.Error(t, err)
		assert.Equal(t, "certificate auth requires both certPath and keyPath", err.Error())
	})

	t.Run("returns error when tls enabled but key path missing", func(t *testing.T) {
		cfg := Bouncer{
			TLS: BouncerTLS{Enabled: true, CertPath: "/path/to/cert"},
		}
		err := cfg.ValidateAuth()
		require.Error(t, err)
		assert.Equal(t, "certificate auth requires both certPath and keyPath", err.Error())
	})
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
		v.Set("bouncer.metrics", true)
		v.Set("bouncer.tickerInterval", "30s")
		v.Set("waf.enabled", true)
		v.Set("waf.timeout", "30s")
		v.Set("waf.apiKey", "test-key")
		v.Set("waf.appSecURL", "http://test.com")

		c, err := New(v)
		assert.NoError(t, err)
		assert.Equal(t, 8080, c.Server.GRPCPort)
		assert.Equal(t, 8081, c.Server.HTTPPort)
		assert.Equal(t, "debug", c.Server.LogLevel)
		assert.Equal(t, "test-key", c.Bouncer.ApiKey)
		assert.Equal(t, "http://test.com", c.Bouncer.LAPIURL)
		assert.Equal(t, []string{"127.0.0.1"}, c.TrustedProxies)
		assert.True(t, c.Bouncer.Metrics)
		assert.Equal(t, "30s", c.Bouncer.TickerInterval)
		assert.True(t, c.WAF.Enabled)
		assert.Equal(t, "test-key", c.WAF.ApiKey)
		assert.Equal(t, "http://test.com", c.WAF.AppSecURL)
	})
}
