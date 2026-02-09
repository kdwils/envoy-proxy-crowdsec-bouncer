//go:build functional

package functional

import (
	"context"
	"encoding/json"
	"io"
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
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	componentmocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestWebhookEvents(t *testing.T) {
	testWebhookEventsWithVersion(t, CrowdsecImages[len(CrowdsecImages)-1])
}

func testWebhookEventsWithVersion(t *testing.T, image string) {
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

	net, err := network.New(t.Context(), network.WithDriver("bridge"))
	require.NoError(t, err, "failed to create network")
	defer net.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API":               "false",
			"DISABLE_AGENT":                   "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {"lapi"}},
		WaitingFor:     wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
	}

	lapiContainer, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: lapiReq,
		Started:          true,
	})
	require.NoError(t, err, "failed to start LAPI container")
	defer lapiContainer.Terminate(t.Context())

	lapiHost, err := lapiContainer.Host(t.Context())
	require.NoError(t, err)
	lapiPort, err := lapiContainer.MappedPort(t.Context(), "8080")
	require.NoError(t, err)

	hostLAPI := url.URL{
		Scheme: "http",
		Host:   lapiHost + ":" + lapiPort.Port(),
	}

	_, out, err := lapiContainer.Exec(t.Context(), []string{
		"cscli", "bouncers", "add", "testBouncer",
	})
	require.NoError(t, err, "failed to add bouncer")
	b, err := io.ReadAll(out)
	require.NoError(t, err)
	key, err := extractAPIKey(string(b))
	require.NoError(t, err, "failed to extract API key")

	_, _, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "decisions", "add", "--type", "ban", "--value", "192.168.10.1",
	})
	require.NoError(t, err, "failed to add ban decision")

	_, _, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "decisions", "add", "--type", "captcha", "--value", "192.168.10.2",
	})
	require.NoError(t, err, "failed to add captcha decision")

	v := viper.New()
	v.Set("server.grpcPort", 8080)
	v.Set("server.httpPort", 8081)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", false)
	v.Set("waf.enabled", false)
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

	mockProvider := componentmocks.NewMockCaptchaProvider(ctrl)
	mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), "success", gomock.Any()).Return(true, nil).AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), gomock.Not("success"), gomock.Any()).Return(false, nil).AnyTimes()

	captchaService, err := components.NewCaptchaService(cfg.Captcha, http.DefaultClient)
	require.NoError(t, err)
	captchaService.Provider = mockProvider

	testBouncer, err := bouncer.New(cfg)
	require.NoError(t, err)
	testBouncer.CaptchaService = captchaService
	go testBouncer.Sync(ctx)

	notifier := webhook.New(
		[]webhook.Subscription{
			{
				URL: webhookSrv.URL,
				Events: []webhook.EventType{
					webhook.EventRequestAllowed,
					webhook.EventRequestBlocked,
					webhook.EventCaptchaRequired,
					webhook.EventCaptchaVerified,
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

	srv := server.NewServer(cfg, testBouncer, captchaService, notifier, templateStore, slogger)
	go func() {
		if err := srv.ServeDual(ctx); err != nil && err != context.Canceled {
			t.Logf("server error: %v", err)
		}
	}()

	time.Sleep(5 * time.Second)

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
		require.Equal(t, int32(0), check.Status.Code)

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
		require.Equal(t, int32(403), check.Status.Code)

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
		require.Equal(t, int32(302), check.Status.Code)

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
		require.Equal(t, int32(302), check.Status.Code)

		waitForEvent(t, 3*time.Second)

		deniedResponse := check.GetDeniedResponse()
		require.NotNil(t, deniedResponse, "expected denied response for captcha redirect")
		require.Len(t, deniedResponse.Headers, 1, "expected one location header")

		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)

		challengeToken := locationURL.Query().Get("challengeToken")
		require.NotEmpty(t, challengeToken, "expected challenge token in redirect")

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
