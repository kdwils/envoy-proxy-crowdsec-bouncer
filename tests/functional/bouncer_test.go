//go:build functional
// +build functional

package functional

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/cmd"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestBouncer(t *testing.T) {
	ctx := context.Background()
	lapiReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.6.8",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API": "false",
			"DISABLE_AGENT":     "true",
			"LOCAL_API_URL":     "http://localhost:8080",
		},
		WaitingFor: wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
	}

	lapiContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: lapiReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start container: %v", err)
	}
	defer lapiContainer.Terminate(ctx)

	host, err := lapiContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := lapiContainer.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatal(err)
	}

	LAPIURL := url.URL{
		Scheme: "http",
		Host:   host + ":" + port.Port(),
	}

	_, out, err := lapiContainer.Exec(ctx, []string{
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

	_, _, err = lapiContainer.Exec(ctx, []string{
		"cscli", "decisions", "add", "--type", "ban", "--value", "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("failed to exec: %v", err)
	}

	trustedProxies := []string{"10.0.0.1"}

	rootCmd := cmd.ServeCmd.Root()
	rootCmd.SetArgs([]string{"serve"})
	viper.Set("server.port", 8080)
	viper.Set("server.logLevel", "debug")
	viper.Set("bouncer.apiKey", key)
	viper.Set("bouncer.lapiURL", LAPIURL.String())
	viper.Set("trustedProxies", trustedProxies)
	viper.Set("bouncer.tickerInterval", "1s")
	viper.Set("bouncer.enabled", true)
	viper.Set("waf.enabled", false)

	go func() {
		err = rootCmd.Execute()
		if err != nil {
			log.Fatalf("failed to execute serve command: %v", err)
		}
	}()

	time.Sleep(5 * time.Second) // wait for server to start

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("Test Bouncer non-banned", func(t *testing.T) {
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "192.168.1.1",
							},
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

	t.Run("Test Bouncer banned", func(t *testing.T) {
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "192.168.1.100",
							},
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("xff with trusted proxy", func(t *testing.T) {
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "192.168.1.100",
							},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"x-forwarded-for": "192.168.1.100,10.0.0.1",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("ban decision removed", func(t *testing.T) {
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "192.168.1.100",
							},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"x-forwarded-for": "192.168.1.100,10.0.0.1",
						},
					},
				},
			},
		}

		_, _, err = lapiContainer.Exec(ctx, []string{
			"cscli", "decisions", "delete", "-i", "192.168.1.100",
		})
		if err != nil {
			t.Fatalf("failed to exec: %v", err)
		}

		time.Sleep(2 * time.Second)

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

}

func extractAPIKey(output string) (string, error) {
	lines := strings.Split(output, "\n")
	if len(lines) < 3 {
		return "", fmt.Errorf("expected at least 3 lines, got %d", len(lines))
	}

	key := lines[2]
	return strings.TrimSpace(key), nil
}
