//go:build functional

package functional

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/captcha"
	captchamocks "github.com/kdwils/envoy-proxy-bouncer/captcha/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func testWebhookEvents(t *testing.T, env *testEnv) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	received := make(chan webhook.Event, 10)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event webhook.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- event
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	env.resetDecisions(t)
	env.addDecision(t, "--type", "ban", "--value", "192.168.10.1")
	env.addDecision(t, "--type", "captcha", "--value", "192.168.10.2")

	v := newTestViper()
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("bouncer.tickerInterval", "1s")
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

	mockProvider := captchamocks.NewMockCaptchaProvider(ctrl)
	mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), "success", gomock.Any()).Return(true, nil).AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), gomock.Not("success"), gomock.Any()).Return(false, nil).AnyTimes()

	rec := recorder.NewNoOp()

	captchaService, err := captcha.NewCaptchaService(cfg.Captcha, http.DefaultClient, rec)
	require.NoError(t, err)
	captchaService.Provider = mockProvider

	testBouncer, err := bouncer.New(cfg, rec, http.DefaultClient)
	require.NoError(t, err)
	testBouncer.CaptchaService = captchaService
	go testBouncer.Sync(ctx)

	waitForDecision(t, testBouncer.DecisionCache, "192.168.10.1", true, 10*time.Second)
	waitForDecision(t, testBouncer.DecisionCache, "192.168.10.2", true, 10*time.Second)

	notifier := webhook.New(
		[]config.Subscription{
			{
				URL: webhookSrv.URL,
				Events: []string{
					"request_allowed",
					"request_blocked",
					"captcha_required",
					"captcha_verified",
				},
			},
		},
		"",
		5*time.Second,
		100,
		http.DefaultClient,
	)
	go notifier.Start(ctx)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, captchaService, notifier, templateStore, slogger, rec, nil)
	stop := startServer(t, ctx, srv, "localhost:8080")
	defer stop()

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	waitForEvent := func(t *testing.T, timeout time.Duration) webhook.Event {
		t.Helper()
		select {
		case event := <-received:
			return event
		case <-time.After(timeout):
			t.Fatal("timed out waiting for webhook event")
			return webhook.Event{}
		}
	}

	t.Run("request_allowed", func(t *testing.T) {
		req := createCheckRequest("10.0.0.1", createHttpRequest("GET", "/hello", "example.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))

		got := waitForEvent(t, 3*time.Second)
		want := webhook.Event{
			Type:      webhook.EventRequestAllowed,
			Timestamp: got.Timestamp,
			IP:        "10.0.0.1",
			Action:    "allow",
			Reason:    "ok",
			Request:   got.Request,
		}
		assert.Equal(t, want, got)
	})

	t.Run("request_blocked", func(t *testing.T) {
		req := createCheckRequest("192.168.10.1", createHttpRequest("GET", "/restricted", "example.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))

		got := waitForEvent(t, 3*time.Second)
		want := webhook.Event{
			Type:      webhook.EventRequestBlocked,
			Timestamp: got.Timestamp,
			IP:        "192.168.10.1",
			Action:    "ban",
			Reason:    "manual 'ban' from 'localhost'",
			Request:   got.Request,
		}
		assert.Equal(t, want, got)
	})

	t.Run("captcha_required", func(t *testing.T) {
		req := createCheckRequest("192.168.10.2", createHttpRequest("GET", "/protected", "example.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		got := waitForEvent(t, 3*time.Second)
		want := webhook.Event{
			Type:      webhook.EventCaptchaRequired,
			Timestamp: got.Timestamp,
			IP:        "192.168.10.2",
			Action:    "captcha",
			Reason:    "captcha required",
			Request:   got.Request,
		}
		assert.Equal(t, want, got)
	})

	t.Run("captcha_verified", func(t *testing.T) {
		req := createCheckRequest("192.168.10.2", createHttpRequest("GET", "/protected-verify", "example.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		challengeToken := extractChallengeToken(t, check)
		assert.Equal(t, marshalProto(t, wantRedirectResponse(challengeToken)), marshalProto(t, check))

		waitForEvent(t, 3*time.Second)

		form := url.Values{}
		form.Add("challengeToken", challengeToken)
		form.Add("captchaResponse", "success")

		httpReq, err := http.NewRequest("POST", "http://localhost:8081/captcha/verify", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", "192.168.10.2")

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)

		got := waitForEvent(t, 3*time.Second)
		want := webhook.Event{
			Type:      webhook.EventCaptchaVerified,
			Timestamp: got.Timestamp,
			IP:        "192.168.10.2",
			Action:    "allow",
			Reason:    "captcha verified",
			Request:   got.Request,
		}
		assert.Equal(t, want, got)
	})
}
