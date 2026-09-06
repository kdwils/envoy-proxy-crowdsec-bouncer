//go:build functional

package functional

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func testHealthProbes(t *testing.T, env *testEnv) {
	v := newTestViper()
	v.Set("bouncer.apiKey", env.apiKey)
	v.Set("bouncer.lapiURL", env.lapiURL)
	v.Set("bouncer.tickerInterval", "1s")

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	rec := recorder.NewNoOp()

	decisionCache, w, captchaService, metricsService, err := bouncer.NewComponents(cfg, rec, http.DefaultClient)
	require.NoError(t, err)

	testBouncer, err := bouncer.New(cfg, rec, decisionCache, w, captchaService, metricsService)
	require.NoError(t, err)
	go testBouncer.Sync(ctx)

	waitForDecisionCache(t, testBouncer.DecisionCache, 10*time.Second)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, testBouncer.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
	stop := startServer(t, ctx, srv, "localhost:8080")
	defer stop()

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	t.Run("Liveness always returns serving", func(t *testing.T) {
		resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
			Service: "liveness",
		})
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
	})

	t.Run("Readiness returns serving once decision cache is synced", func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Second)
		var resp *grpc_health_v1.HealthCheckResponse
		for time.Now().Before(deadline) && (resp == nil || resp.Status != grpc_health_v1.HealthCheckResponse_SERVING) {
			resp, err = healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "readiness",
			})
			require.NoError(t, err)
			if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				time.Sleep(100 * time.Millisecond)
			}
		}
		assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
	})

	t.Run("Liveness remains serving throughout lifecycle", func(t *testing.T) {
		for range 5 {
			resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "liveness",
			})
			require.NoError(t, err)
			assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
			time.Sleep(500 * time.Millisecond)
		}
	})

	t.Run("Readiness stays serving after decision cache is ready", func(t *testing.T) {
		for range 5 {
			resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "readiness",
			})
			require.NoError(t, err)
			assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
			time.Sleep(500 * time.Millisecond)
		}
	})
}

func TestHealthProbesWithDisabledBouncer(t *testing.T) {
	v := newTestViper()
	v.Set("server.grpcPort", 8082)
	v.Set("bouncer.enabled", false)

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	rec := recorder.NewNoOp()

	decisionCache, w, captchaService, metricsService, err := bouncer.NewComponents(cfg, rec, http.DefaultClient)
	require.NoError(t, err)

	testBouncer, err := bouncer.New(cfg, rec, decisionCache, w, captchaService, metricsService)
	require.NoError(t, err)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, testBouncer, testBouncer.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
	stop := startServer(t, ctx, srv, "localhost:8082")
	defer stop()

	conn, err := grpc.NewClient("localhost:8082", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	t.Run("Liveness returns serving when bouncer disabled", func(t *testing.T) {
		resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
			Service: "liveness",
		})
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
	})

	t.Run("Readiness returns serving immediately when bouncer disabled", func(t *testing.T) {
		deadline := time.Now().Add(3 * time.Second)
		var resp *grpc_health_v1.HealthCheckResponse
		for time.Now().Before(deadline) && (resp == nil || resp.Status != grpc_health_v1.HealthCheckResponse_SERVING) {
			resp, err = healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "readiness",
			})
			require.NoError(t, err)
			if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				time.Sleep(100 * time.Millisecond)
			}
		}
		assert.Equal(t, marshalProto(t, &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}), marshalProto(t, resp))
	})
}
