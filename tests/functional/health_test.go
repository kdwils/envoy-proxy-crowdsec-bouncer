//go:build functional

package functional

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthProbes(t *testing.T) {
	for _, image := range CrowdsecImages {
		t.Run(image, func(t *testing.T) {
			testHealthProbesWithVersion(t, image)
		})
	}
}

func testHealthProbesWithVersion(t *testing.T, image string) {
	network, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer network.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API":               "false",
			"DISABLE_AGENT":                   "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Networks:       []string{network.Name},
		NetworkAliases: map[string][]string{network.Name: {"lapi"}},
		WaitingFor:     wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
	}

	lapiContainer, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: lapiReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start container: %v", err)
	}
	defer lapiContainer.Terminate(t.Context())

	lapiHost, err := lapiContainer.Host(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lapiPort, err := lapiContainer.MappedPort(t.Context(), "8080")
	if err != nil {
		t.Fatal(err)
	}

	hostLAPI := url.URL{
		Scheme: "http",
		Host:   lapiHost + ":" + lapiPort.Port(),
	}

	_, out, err := lapiContainer.Exec(t.Context(), []string{
		"cscli", "bouncers", "add", "testBouncer",
	})
	if err != nil {
		t.Fatalf("failed to exec: %v", err)
	}
	b, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	key, err := extractAPIKey(string(b))
	if err != nil {
		t.Fatalf("failed to extract api key: %v", err)
	}

	v := viper.New()
	v.Set("server.grpcPort", 8080)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("captcha.enabled", false)

	config, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(config.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	bouncer, err := bouncer.New(config)
	require.NoError(t, err)
	go bouncer.Sync(ctx)

	templateStore, err := template.NewStore(template.Config{})
	if err != nil {
		log.Fatalf("failed to create template store: %v", err)
	}

	server := server.NewServer(config, bouncer, bouncer.CaptchaService, templateStore, slogger)

	go func() {
		err := server.ServeDual(ctx)
		if err != nil && err != context.Canceled {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	t.Run("Liveness always returns serving", func(t *testing.T) {
		resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
			Service: "liveness",
		})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("Readiness returns not_serving initially then serving after sync", func(t *testing.T) {
		resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
			Service: "readiness",
		})
		require.NoError(t, err)

		status := resp.Status
		if status != grpc_health_v1.HealthCheckResponse_SERVING {
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, status)
			time.Sleep(3 * time.Second)

			resp, err = healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "readiness",
			})
			require.NoError(t, err)
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
		}
	})

	t.Run("Liveness remains serving throughout lifecycle", func(t *testing.T) {
		for range 5 {
			resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "liveness",
			})
			require.NoError(t, err)
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
			time.Sleep(500 * time.Millisecond)
		}
	})

	t.Run("Readiness stays serving after decision cache is ready", func(t *testing.T) {
		time.Sleep(5 * time.Second)

		for range 5 {
			resp, err := healthClient.Check(context.TODO(), &grpc_health_v1.HealthCheckRequest{
				Service: "readiness",
			})
			require.NoError(t, err)
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
			time.Sleep(500 * time.Millisecond)
		}
	})
}
