package config

import (
	"strings"

	"github.com/spf13/viper"
)

func GetViper(cfgFile string) *viper.Viper {
	v := viper.New()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}

	v.SetEnvPrefix("ENVOY_BOUNCER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", ""))
	v.AutomaticEnv()

	v.SetDefault("trustedProxies", []string{})
	v.SetDefault("trustedIPHeader", "")
	v.SetDefault("exemptIPs", []string{})

	v.SetDefault("server.grpcPort", 8080)
	v.SetDefault("server.httpPort", 8081)
	v.SetDefault("server.logLevel", "info")

	v.SetDefault("bouncer.apiKey", "")
	v.SetDefault("bouncer.lapiURL", "")
	v.SetDefault("bouncer.enabled", true)
	v.SetDefault("bouncer.metrics", false)
	v.SetDefault("bouncer.tickerInterval", "10s")
	v.SetDefault("bouncer.metricsInterval", "10m")
	v.SetDefault("bouncer.banStatusCode", 403)
	v.SetDefault("bouncer.tls.enabled", false)
	v.SetDefault("bouncer.tls.certPath", "")
	v.SetDefault("bouncer.tls.keyPath", "")
	v.SetDefault("bouncer.tls.caPath", "")
	v.SetDefault("bouncer.tls.insecureSkipVerify", false)

	v.SetDefault("waf.enabled", false)
	v.SetDefault("waf.apiKey", "")
	v.SetDefault("waf.appSecURL", "")
	v.SetDefault("waf.httpTimeout", "5s")
	v.SetDefault("waf.failOpen", false)

	v.SetDefault("captcha.enabled", false)
	v.SetDefault("captcha.provider", "")
	v.SetDefault("captcha.siteKey", "")
	v.SetDefault("captcha.secretKey", "")
	v.SetDefault("captcha.signingKey", "")
	v.SetDefault("captcha.callbackURL", "")
	v.SetDefault("captcha.cookieDomain", "")
	v.SetDefault("captcha.cookieName", "session")
	v.SetDefault("captcha.secureCookie", true)
	v.SetDefault("captcha.timeout", "10s")
	v.SetDefault("captcha.challengeDuration", "5m")
	v.SetDefault("captcha.sessionDuration", "15m")
	v.SetDefault("captcha.disableChallengeReplayProtection", false)

	v.SetDefault("prometheus.enabled", false)
	v.SetDefault("prometheus.port", 9090)

	v.SetDefault("webhook.subscriptions", nil)
	v.SetDefault("webhook.signingKey", "")
	v.SetDefault("webhook.timeout", "5s")
	v.SetDefault("webhook.bufferSize", 100)

	v.SetDefault("templates.deniedTemplatePath", "")
	v.SetDefault("templates.deniedTemplateHeaders", "text/html; charset=utf-8")
	v.SetDefault("templates.showDeniedPage", true)
	v.SetDefault("templates.captchaTemplatePath", "")
	v.SetDefault("templates.captchaTemplateHeaders", "text/html; charset=utf-8")

	v.SetDefault("http.maxIdleConns", 1000)
	v.SetDefault("http.maxIdleConnsPerHost", 100)
	v.SetDefault("http.idleConnTimeout", "90s")
	v.SetDefault("http.tlsHandshakeTimeout", "10s")

	return v
}
