//go:build functional

package functional

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createCheckRequest(ip string, httpRequest *auth.AttributeContext_HttpRequest) *auth.CheckRequest {
	return &auth.CheckRequest{
		Attributes: &auth.AttributeContext{
			Source: &auth.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: ip,
						},
					},
				},
			},
			Request: &auth.AttributeContext_Request{
				Http: httpRequest,
			},
		},
	}
}

func createHttpRequest(method, path, authority string, extraHeaders map[string]string) *auth.AttributeContext_HttpRequest {
	headers := map[string]string{
		":method":    method,
		":path":      path,
		":authority": authority,
		":scheme":    "http",
		"User-Agent": "test-agent",
	}

	maps.Copy(headers, extraHeaders)

	return &auth.AttributeContext_HttpRequest{
		Headers:  headers,
		Protocol: "HTTP/1.1",
	}
}

func testBouncer(t *testing.T, env *testEnv) {
	env.resetDecisions(t)
	env.addDecision(t, "--type", "ban", "--value", "192.168.1.100")

	v := viper.New()
	v.Set("server.grpcPort", 8080)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("trustedProxies", []string{"10.0.0.1"})
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", env.apiKey)
	v.Set("waf.appsecURL", env.appsecBanURL)
	v.Set("exemptIPs", []string{"172.16.0.0/12"})
	v.Set("captcha.enabled", false)

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	reg := prometheus.NewRegistry()
	rec, err := recorder.New(reg)
	require.NoError(t, err)

	testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
	require.NoError(t, err)
	go testBouncer.Sync(ctx)

	if cfg.Bouncer.Metrics {
		go func() {
			if err := testBouncer.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	waitForDecision(t, testBouncer.DecisionCache, "192.168.1.100", true, 10*time.Second)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, testBouncer.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, reg)
	stop := startServer(t, ctx, srv, "localhost:8080")
	defer stop()

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("Test Bouncer non-banned", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("Test banned decision", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))
	})

	t.Run("xff with trusted proxy", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))
	})

	t.Run("ban decision removed", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

		originCounts := testBouncer.DecisionCache.GetOriginCounts()
		assert.Equal(t, map[string]int{"cscli": 1}, originCounts)

		env.deleteDecision(t, "-i", "192.168.1.100")

		waitForDecision(t, testBouncer.DecisionCache, "192.168.1.100", false, 10*time.Second)

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("trigger inline", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))
	})

	t.Run("ipv4 cidr range ban", func(t *testing.T) {
		env.addDecision(t, "--range", "10.0.0.0/8")

		waitForDecision(t, testBouncer.DecisionCache, "10.50.100.200", true, 10*time.Second)

		req := createCheckRequest("10.50.100.200", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))
	})

	t.Run("ipv4 cidr range outside not banned", func(t *testing.T) {
		req := createCheckRequest("172.16.0.1", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("ipv4 cidr range delete allows traffic", func(t *testing.T) {
		env.deleteDecision(t, "--range", "10.0.0.0/8")

		waitForDecision(t, testBouncer.DecisionCache, "10.50.100.200", false, 10*time.Second)

		req := createCheckRequest("10.50.100.200", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("Test captcha decision with disabled captcha service", func(t *testing.T) {
		req := createCheckRequest("192.168.2.100", createHttpRequest("GET", "/protected", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("Verify metrics after basic scenarios", func(t *testing.T) {
		snapshot := testBouncer.MetricsService.GetSnapshot()

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		assert.Equal(t, crowdsec.Metric{
			Name:   "processed",
			Unit:   "request",
			Value:  5,
			Labels: map[string]string{"origin": "CAPI", "remediation": "bypass"},
		}, bypassMetric)

		banMetric, ok := snapshot["CAPI:ban"]
		require.True(t, ok, "expected CAPI:ban metric to exist")
		assert.Equal(t, crowdsec.Metric{
			Name:   "dropped",
			Unit:   "request",
			Value:  4,
			Labels: map[string]string{"origin": "CAPI", "remediation": "ban"},
		}, banMetric)

		originCounts := testBouncer.DecisionCache.GetOriginCounts()
		assert.Equal(t, map[string]int{"cscli": 0}, originCounts)

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(5), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 5 allowed requests")
		assert.Equal(t, float64(4), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("ban")), "expected 4 banned requests")
	})

	t.Run("Test exempt IP bypasses all checks", func(t *testing.T) {
		env.addDecision(t, "--type", "ban", "--value", "172.16.0.1")
		env.addDecision(t, "--range", "10.0.0.0/8")

		waitForDecision(t, testBouncer.DecisionCache, "10.0.0.1", true, 10*time.Second)

		req := createCheckRequest("172.16.0.1", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))

		reqWAF := createCheckRequest("172.16.0.1", createHttpRequest("GET", "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", "my-host.com", nil))
		checkWAF, err := client.Check(t.Context(), reqWAF)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, checkWAF))

		reqBanned := createCheckRequest("10.0.0.1", createHttpRequest("GET", "/testing", "my-host.com", nil))
		checkBanned, err := client.Check(t.Context(), reqBanned)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, checkBanned))

		snapshot := testBouncer.MetricsService.GetSnapshot()

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		assert.Equal(t, crowdsec.Metric{
			Name:   "processed",
			Unit:   "request",
			Value:  7,
			Labels: map[string]string{"origin": "CAPI", "remediation": "bypass"},
		}, bypassMetric)

		banMetric, ok := snapshot["CAPI:ban"]
		require.True(t, ok, "expected CAPI:ban metric to exist")
		assert.Equal(t, crowdsec.Metric{
			Name:   "dropped",
			Unit:   "request",
			Value:  5,
			Labels: map[string]string{"origin": "CAPI", "remediation": "ban"},
		}, banMetric)

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(7), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 7 allowed requests")
		assert.Equal(t, float64(5), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("ban")), "expected 5 banned requests")

		env.deleteDecision(t, "-i", "172.16.0.1")
		env.deleteDecision(t, "--range", "10.0.0.0/8")
	})
}

func testBouncerCaptcha(t *testing.T, env *testEnv) {
	env.resetDecisions(t)
	env.addDecision(t, "--type", "captcha", "--value", "192.168.1.100")

	v := viper.New()
	v.Set("server.grpcPort", 8080)
	v.Set("server.httpPort", 8081)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("trustedProxies", []string{"10.0.0.1"})
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", env.apiKey)
	v.Set("waf.appsecURL", env.appsecCaptchaURL)
	v.Set("captcha.enabled", true)
	v.Set("captcha.provider", "recaptcha")
	v.Set("captcha.siteKey", "test-site-key")
	v.Set("captcha.secretKey", "test-secret-key")
	v.Set("captcha.signingKey", "test-signing-key-for-jwt-sessions")
	v.Set("captcha.callbackURL", "http://localhost")
	v.Set("captcha.cookieDomain", "")
	v.Set("captcha.cookieName", "session")
	v.Set("captcha.secureCookie", false)
	v.Set("captcha.challengeDuration", "5m")
	v.Set("captcha.sessionDuration", "1h")

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	reg := prometheus.NewRegistry()
	rec, err := recorder.New(reg)
	require.NoError(t, err)

	testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
	require.NoError(t, err)
	go testBouncer.Sync(ctx)

	if cfg.Bouncer.Metrics {
		go func() {
			if err := testBouncer.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	waitForDecision(t, testBouncer.DecisionCache, "192.168.1.100", true, 10*time.Second)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, testBouncer.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, reg)
	stop := startServer(t, ctx, srv, "localhost:8080")
	defer stop()

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("Test captcha decision triggers captcha challenge and page is served", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		session, exists := testBouncer.CaptchaService.GetSession(challengeToken)
		require.True(t, exists)
		require.NotNil(t, session)
		require.NotEmpty(t, session.CreatedAt)
		require.NotEmpty(t, session.ExpiresAt)

		redirectParams := make(url.Values)
		redirectParams.Set("challengeToken", challengeToken)
		assert.Equal(t, components.CaptchaSession{
			ID:           challengeToken,
			OriginalURL:  "http://my-host.com/protected",
			CreatedAt:    session.CreatedAt,
			ExpiresAt:    session.ExpiresAt,
			Provider:     "recaptcha",
			SiteKey:      "test-site-key",
			CallbackURL:  "http://localhost/captcha",
			RedirectURL:  "http://my-host.com/protected",
			ChallengeURL: "http://localhost/captcha/challenge?" + redirectParams.Encode(),
		}, *session)

		challengeURL := fmt.Sprintf("http://localhost:8081/captcha/challenge?challengeToken=%s", challengeToken)
		resp, err := http.Get(challengeURL)
		require.NoError(t, err, "Failed to make HTTP request to challenge page")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "<title>Security Verification</title>")
		require.Contains(t, string(body), "test-site-key")
	})

	t.Run("Test WAF trigger captcha flow", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		session, exists := testBouncer.CaptchaService.GetSession(challengeToken)
		require.True(t, exists)
		require.NotNil(t, session)
		require.NotEmpty(t, session.CreatedAt)
		require.NotEmpty(t, session.ExpiresAt)

		redirectParams := make(url.Values)
		redirectParams.Set("challengeToken", challengeToken)
		assert.Equal(t, components.CaptchaSession{
			ID:           challengeToken,
			OriginalURL:  "http://my-host.com/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl",
			CreatedAt:    session.CreatedAt,
			ExpiresAt:    session.ExpiresAt,
			Provider:     "recaptcha",
			SiteKey:      "test-site-key",
			CallbackURL:  "http://localhost/captcha",
			RedirectURL:  "http://my-host.com/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl",
			ChallengeURL: "http://localhost/captcha/challenge?" + redirectParams.Encode(),
		}, *session)
	})

	t.Run("Test non-captcha decision allows through", func(t *testing.T) {
		req := createCheckRequest("192.168.1.200", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("Test invalid redirect URL is rejected", func(t *testing.T) {
		captchaService, err := components.NewCaptchaService(cfg.Captcha, &http.Client{}, rec)
		require.NoError(t, err)

		session, err := captchaService.CreateSession("192.168.1.100", "javascript:alert('xss')", "")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")

		session, err = captchaService.CreateSession("192.168.1.100", "/relative/path", "")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")

		session, err = captchaService.CreateSession("192.168.1.100", "ftp://example.com/file", "")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")
	})

	t.Run("Test IP mismatch during verification", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected-ip-test", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpClient := &http.Client{}
		req2, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("X-Forwarded-For", "10.0.0.1")

		resp, err := httpClient.Do(req2)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Test rate limiting on captcha endpoints", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected-ratelimit-test", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		challengeURL := "http://localhost:8081/captcha/challenge?challengeToken=" + challengeToken
		httpClient := &http.Client{}

		successCount := 0
		rateLimitCount := 0

		for range 25 {
			req, err := http.NewRequest("GET", challengeURL, nil)
			require.NoError(t, err)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")

			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				successCount++
			case http.StatusTooManyRequests:
				rateLimitCount++
			}
		}

		require.Greater(t, successCount, 0)
		require.Greater(t, rateLimitCount, 0)
	})

	t.Run("Verify metrics after captcha scenarios", func(t *testing.T) {
		assert.Equal(t, map[string]crowdsec.Metric{
			"CAPI:bypass": {
				Name:   "processed",
				Unit:   "request",
				Value:  1,
				Labels: map[string]string{"origin": "CAPI", "remediation": "bypass"},
			},
			"CAPI:captcha": {
				Name:   "dropped",
				Unit:   "request",
				Value:  4,
				Labels: map[string]string{"origin": "CAPI", "remediation": "captcha"},
			},
			"active_decisions:cscli": {
				Name:   "active_decisions",
				Unit:   "ip",
				Value:  1,
				Labels: map[string]string{"origin": "cscli"},
			},
		}, testBouncer.MetricsService.GetSnapshot())

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(4), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("captcha")), "expected 4 captcha requests")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 1 allowed request")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaVerificationsTotal.WithLabelValues("failure")), "expected 1 captcha verification failure")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
		assert.Equal(t, float64(5), testutil.ToFloat64(metrics.RateLimitedTotal), "expected 5 rate limited requests (25 requests - 20 burst)")
	})
}

func extractChallengeToken(t *testing.T, check *auth.CheckResponse) string {
	t.Helper()

	deniedResponse := check.GetDeniedResponse()
	require.NotNil(t, deniedResponse)
	require.Len(t, deniedResponse.Headers, 1)

	locationURL, err := url.Parse(deniedResponse.Headers[0].Header.Value)
	require.NoError(t, err)

	challengeToken := locationURL.Query().Get("challengeToken")
	require.NotEmpty(t, challengeToken)

	return challengeToken
}

func extractAPIKey(output string) (string, error) {
	lines := strings.Split(output, "\n")
	if len(lines) < 3 {
		return "", fmt.Errorf("expected at least 3 lines, got %d", len(lines))
	}

	key := lines[2]
	return strings.TrimSpace(key), nil
}
