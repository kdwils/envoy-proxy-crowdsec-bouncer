//go:build functional

package functional

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/captcha"
	captchamocks "github.com/kdwils/envoy-proxy-bouncer/captcha/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/decisions"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/waf"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func testJWTCompleteVerificationFlow(t *testing.T, env *testEnv) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	env.resetDecisions(t)
	env.addDecision(t, "--type", "captcha", "--value", "127.0.0.1")

	v := newTestViper()
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("trustedProxies", []string{"10.0.0.1"})
	v.Set("bouncer.tickerInterval", "1s")
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
	v.Set("captcha.secureCookie", false)
	v.Set("captcha.sessionDuration", "1h")

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	dcRec := recorder.NewNoOp()

	decisionCache, err := decisions.NewCache(cfg.Bouncer, nil, dcRec)
	require.NoError(t, err)

	wafClient, err := waf.NewWAF(cfg.WAF.AppSecURL, cfg.WAF.ApiKey, cfg.WAF.HTTPTimeout, http.DefaultClient)
	require.NoError(t, err)

	mockProvider := captchamocks.NewMockCaptchaProvider(ctrl)
	mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), "success", gomock.Any()).Return(true, nil).AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), gomock.Not("success"), gomock.Any()).Return(false, nil).AnyTimes()

	go decisionCache.Sync(ctx)

	waitForDecisionCache(t, decisionCache, 10*time.Second)
	waitForDecision(t, decisionCache, "127.0.0.1", true, 10*time.Second)

	t.Run("Complete JWT verification flow with cookie bypass", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaService, err := captcha.NewCaptchaService(cfg.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaService

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		testIP := "127.0.0.1"

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)

		verificationCookie := getCookie(resp, "session")
		require.NotNil(t, verificationCookie)
		require.NotEmpty(t, verificationCookie.Value)

		req2 := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
							"cookie":     fmt.Sprintf("session=%s", verificationCookie.Value),
						},
					},
				},
			},
		}

		check2, err := client.Check(context.TODO(), req2)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check2))

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("captcha")), "expected 1 captcha request")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 1 allowed request")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaVerificationsTotal.WithLabelValues("success")), "expected 1 successful captcha verification")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 0 pending captcha challenges after successful verification")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
	})

	t.Run("Multiple requests with same verification cookie bypass captcha", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaService, err := captcha.NewCaptchaService(cfg.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaService

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		testIP := "127.0.0.1"

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		verificationCookie := getCookie(resp, "session")
		require.NotNil(t, verificationCookie)

		for i := range 5 {
			reqWithCookie := &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &corev3.Address{
							Address: &corev3.Address_SocketAddress{
								SocketAddress: &corev3.SocketAddress{Address: testIP},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":method":    "GET",
								":path":      "/protected",
								":authority": "my-host.com",
								":scheme":    "http",
								"cookie":     fmt.Sprintf("session=%s", verificationCookie.Value),
							},
						},
					},
				},
			}

			checkResult, err := client.Check(context.TODO(), reqWithCookie)
			require.NoError(t, err)
			assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, checkResult), "Request %d should bypass captcha with valid cookie", i+1)
		}

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("captcha")), "expected 1 captcha request")
		assert.Equal(t, float64(5), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 5 allowed requests")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaVerificationsTotal.WithLabelValues("success")), "expected 1 successful captcha verification")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 0 pending captcha challenges after successful verification")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
	})

	t.Run("Expired verification token requires new captcha", func(t *testing.T) {
		testIP := "127.0.0.1"

		env.deleteDecision(t, "--ip", testIP)
		waitForDecision(t, decisionCache, testIP, false, 10*time.Second)

		env.addDecision(t, "--type", "captcha", "--value", testIP)
		waitForDecision(t, decisionCache, testIP, true, 10*time.Second)

		cfgShortExpiry := cfg
		cfgShortExpiry.Captcha.SessionDuration = 2 * time.Second

		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaServiceShort, err := captcha.NewCaptchaService(cfgShortExpiry.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaServiceShort.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaServiceShort

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfgShortExpiry, testBouncer, captchaServiceShort, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		verificationCookie := getCookie(resp, "session")
		require.NotNil(t, verificationCookie)

		reqWithCookie := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
							"cookie":     fmt.Sprintf("session=%s", verificationCookie.Value),
						},
					},
				},
			},
		}

		checkWithCookie, err := client.Check(context.TODO(), reqWithCookie)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, checkWithCookie))

		time.Sleep(3 * time.Second)

		checkExpired, err := client.Check(context.TODO(), reqWithCookie)
		require.NoError(t, err)

		expiredChallengeToken := extractChallengeToken(t, checkExpired)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(expiredChallengeToken)), marshalProto(t, checkExpired))

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(2), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("captcha")), "expected 2 captcha requests (initial + re-challenge after session expiry)")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("allow")), "expected 1 allowed request (valid session cookie)")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaVerificationsTotal.WithLabelValues("success")), "expected 1 successful captcha verification")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 1 pending captcha challenge from re-challenge after expiry")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
	})

	t.Run("Expired challenge token rejected", func(t *testing.T) {
		cfgShortChallenge := cfg
		cfgShortChallenge.Captcha.ChallengeDuration = 1 * time.Second

		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaServiceShort, err := captcha.NewCaptchaService(cfgShortChallenge.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaServiceShort.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaServiceShort

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfgShortChallenge, testBouncer, captchaServiceShort, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		session, err := captchaServiceShort.CreateSession("127.0.0.1", "http://example.com/protected", "")
		require.NoError(t, err)
		require.NotNil(t, session)

		retrievedSession, exists := captchaServiceShort.GetSession(session.ID)
		require.True(t, exists)
		require.NotNil(t, retrievedSession)

		time.Sleep(2 * time.Second)

		expiredSession, exists := captchaServiceShort.GetSession(session.ID)
		assert.False(t, exists)
		assert.Nil(t, expiredSession)

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 1 pending-cleanup session: challenge JWT expired but cleanup goroutine (1 min interval) has not yet run")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaExpiredChallengesTotal), "expected 0 expired challenges collected: cleanup has not run yet")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
	})

	t.Run("IP binding enforced on challenge token verification", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaService, err := captcha.NewCaptchaService(cfg.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaService

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		ipA := "127.0.0.1"
		ipB := "192.168.5.5"

		env.addDecision(t, "--type", "captcha", "--value", ipA)
		waitForDecision(t, decisionCache, ipA, true, 10*time.Second)

		reqA := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: ipA},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		checkA, err := client.Check(context.TODO(), reqA)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, checkA)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, checkA))

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", ipB)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "verification should fail when IP doesn't match challenge token")

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("captcha")), "expected 1 captcha request")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaVerificationsTotal.WithLabelValues("failure")), "expected 1 captcha verification error from IP mismatch")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 1 pending captcha challenge (IP mismatch does not decrement pending count)")
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaErrorsTotal), "expected 0 captcha service errors")
	})

	t.Run("DisableChallengeReplayProtection skips cache and metrics, allows replay", func(t *testing.T) {
		testIP := "127.0.0.1"

		env.deleteDecision(t, "--ip", testIP)
		waitForDecision(t, decisionCache, testIP, false, 10*time.Second)

		env.addDecision(t, "--type", "captcha", "--value", testIP)
		waitForDecision(t, decisionCache, testIP, true, 10*time.Second)

		cfgNoReplay := cfg
		cfgNoReplay.Captcha.DisableChallengeReplayProtection = true

		reg := prometheus.NewRegistry()
		rec, err := recorder.New(reg)
		require.NoError(t, err)

		captchaService, err := captcha.NewCaptchaService(cfgNoReplay.Captcha, http.DefaultClient, rec)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
		require.NoError(t, err)
		testBouncer.DecisionCache = decisionCache
		testBouncer.WAF = wafClient
		testBouncer.CaptchaService = captchaService

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfgNoReplay, testBouncer, captchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
		stop := startServer(t, ctx, srv, "localhost:8080")
		defer stop()

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		metrics := rec.GetMetrics()
		assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 0 pending challenges after CreateSession: cache should not be written when replay protection is disabled")

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		verifyURL := "http://localhost:8081/captcha/verify"

		for i := range 2 {
			form := url.Values{}
			form.Add("challengeToken", challengeToken)
			form.Add("captchaResponse", "success")

			httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
			require.NoError(t, err)
			httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			httpReq.Header.Set("X-Forwarded-For", testIP)

			resp, err := httpClient.Do(httpReq)
			require.NoError(t, err)
			resp.Body.Close()

			assert.Equal(t, http.StatusFound, resp.StatusCode, "expected verification %d to succeed when replay protection is disabled", i+1)
			assert.Equal(t, float64(0), testutil.ToFloat64(metrics.CaptchaPendingChallenges), "expected 0 pending challenges after verification %d: metric must not be touched when replay protection is disabled", i+1)
		}
	})
}

func getCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
