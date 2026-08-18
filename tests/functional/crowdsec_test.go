//go:build functional

package functional

import "testing"

func TestCrowdsec(t *testing.T) {
	for _, image := range CrowdsecImages {
		t.Run(image, func(t *testing.T) {
			env := setupEnv(t, image)

			t.Run("bouncer", func(t *testing.T) { testBouncer(t, env) })
			t.Run("bouncer-captcha", func(t *testing.T) { testBouncerCaptcha(t, env) })
			t.Run("jwt", func(t *testing.T) { testJWTCompleteVerificationFlow(t, env) })
			t.Run("health", func(t *testing.T) { testHealthProbes(t, env) })
			t.Run("webhook", func(t *testing.T) { testWebhookEvents(t, env) })
			t.Run("tls", func(t *testing.T) { testBouncerTLS(t, env) })
		})
	}
}
