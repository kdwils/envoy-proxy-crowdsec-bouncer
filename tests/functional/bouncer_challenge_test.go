//go:build functional

package functional

import (
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func testBouncerChallenge(t *testing.T, env *testEnv, appsecChallengeURL string) {
	v := newTestViper()
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.metrics", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", env.apiKey)
	v.Set("waf.appsecURL", appsecChallengeURL)

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	reg := prometheus.NewRegistry()
	rec, err := recorder.New(reg)
	require.NoError(t, err)

	decisionCache, w, captchaService, metricsService, err := bouncer.NewComponents(cfg, rec, http.DefaultClient)
	require.NoError(t, err)

	testBouncer, err := bouncer.New(cfg, rec, decisionCache, w, captchaService, metricsService)
	require.NoError(t, err)
	go testBouncer.Sync(ctx)

	if cfg.Bouncer.Metrics {
		go func() {
			if err := testBouncer.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	waitForDecisionCache(t, testBouncer.DecisionCache, 10*time.Second)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, testBouncer.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, reg)
	stop := startServer(t, ctx, srv, "localhost:8080")
	defer stop()

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("Test in-band request receives AppSec native challenge", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(t.Context(), req)
		require.NoError(t, err)

		denied := check.GetDeniedResponse()
		require.NotNil(t, denied)

		assert.Equal(t, envoy_type.StatusCode_OK, denied.Status.Code)

		headers := make(map[string]string, len(denied.Headers))
		for _, h := range denied.Headers {
			headers[h.Header.Key] = h.Header.Value
		}
		assert.Equal(t, "text/html", headers["Content-Type"])
		assert.Equal(t, "no-cache, no-store", headers["Cache-Control"])
		assert.NotEmpty(t, headers["Content-Security-Policy"])

		assert.NotEmpty(t, denied.Body)
		assert.Contains(t, denied.Body, "<title>CrowdSec Challenge</title>")
	})

	t.Run("Verify metrics after challenge scenario", func(t *testing.T) {
		metrics := rec.GetMetrics()
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("challenge")), "expected 1 challenge request")
		assert.Equal(t, float64(1), testutil.ToFloat64(metrics.WAFRequestsTotal.WithLabelValues("challenge")), "expected 1 challenge WAF request")
	})
}
