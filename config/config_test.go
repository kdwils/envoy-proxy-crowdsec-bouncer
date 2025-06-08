package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Run("nil viper returns error", func(t *testing.T) {
		c, err := New(nil)
		assert.Error(t, err)
		assert.Equal(t, "viper not initialized", err.Error())
		assert.Empty(t, c)
	})

	t.Run("valid viper config", func(t *testing.T) {
		v := viper.New()
		v.Set("server.port", 8080)
		v.Set("server.logLevel", "debug")
		v.Set("bouncer.apiKey", "test-key")
		v.Set("bouncer.apiURL", "http://test.com")
		v.Set("bouncer.trustedProxies", []string{"127.0.0.1"})
		v.Set("bouncer.metrics", true)
		v.Set("bouncer.tickerInterval", "30s")

		c, err := New(v)
		assert.NoError(t, err)
		assert.Equal(t, 8080, c.Server.Port)
		assert.Equal(t, "debug", c.Server.LogLevel)
		assert.Equal(t, "test-key", c.Bouncer.ApiKey)
		assert.Equal(t, "http://test.com", c.Bouncer.ApiURL)
		assert.Equal(t, []string{"127.0.0.1"}, c.Bouncer.TrustedProxies)
		assert.True(t, c.Bouncer.Metrics)
		assert.Equal(t, "30s", c.Bouncer.TickerInterval)
	})
}
