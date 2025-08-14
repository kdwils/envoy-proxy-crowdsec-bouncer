//go:build functional

package functional

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/cmd"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

type credFile struct {
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	URL      string `yaml:"url"`
}

func TestBouncer(t *testing.T) {
	network, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer network.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.6.11",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API": "false",
			"DISABLE_AGENT":     "true",
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

	// URL reachable from the host (used by the bouncer running in this test process)
	hostLAPI := url.URL{
		Scheme: "http",
		Host:   lapiHost + ":" + lapiPort.Port(),
	}

	// URL for container-to-container communication inside the Docker network (uses network alias)
	appsecLAPI := url.URL{
		Scheme: "http",
		Host:   "lapi:8080",
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

	_, _, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "decisions", "add", "--type", "ban", "--value", "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("failed to exec: %v", err)
	}

	agentUser := "appsec-agent"
	agentPass := "appsec-pass"
	_, out, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "machines", "add", agentUser, "--password", agentPass, "-f", "/tmp/creds.yaml",
	})
	if err != nil {
		t.Fatalf("failed to add machine: %v", err)
	}

	creds := credFile{
		URL:      appsecLAPI.String(),
		Login:    agentUser,
		Password: agentPass,
	}

	b, err = yaml.Marshal(creds)
	if err != nil {
		t.Fatalf("failed to marshal creds")
	}

	tmpFile, err := os.CreateTemp("", "local_api_creds-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(b)); err != nil {
		t.Fatalf("failed to write creds to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	appsecReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.6.11",
		Networks:     []string{network.Name},
		ExposedPorts: []string{"7422/tcp", "6060/tcp"},
		Env: map[string]string{
			"LOCAL_API_URL":     appsecLAPI.String(),
			"DISABLE_LOCAL_API": "true",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./configs/acquis.yaml",
				ContainerFilePath: "/etc/crowdsec/acquis.yaml",
				FileMode:          0644,
			},
			{
				HostFilePath:      "./configs/appsec.yaml",
				ContainerFilePath: "/etc/crowdsec/appsec-configs/appsec-config.yaml",
				FileMode:          0644,
			},
			{
				HostFilePath:      "./configs/appsec-generic-test.yaml",
				ContainerFilePath: "/etc/crowdsec/appsec-rules/appsec-generic-test.yaml",
				FileMode:          0644,
			},
			{
				HostFilePath:      tmpFile.Name(),
				ContainerFilePath: "/staging/etc/crowdsec/local_api_credentials.yaml",
				FileMode:          0644,
			},
		},
		WaitingFor: wait.ForHTTP("/metrics").WithPort("6060/tcp").WithStartupTimeout(30 * time.Second),
	}

	appsecContainer, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: appsecReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start appsec container: %v", err)
	}
	defer appsecContainer.Terminate(t.Context())

	appsecHost, err := appsecContainer.Host(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	appsecPort, err := appsecContainer.MappedPort(t.Context(), "7422")
	if err != nil {
		t.Fatal(err)
		t.FailNow()
	}

	appsecURL := url.URL{
		Scheme: "http",
		Host:   appsecHost + ":" + appsecPort.Port(),
	}

	trustedProxies := []string{"10.0.0.1"}

	rootCmd := cmd.ServeCmd.Root()
	rootCmd.SetArgs([]string{"serve"})
	viper.Set("server.port", 8080)
	viper.Set("server.logLevel", "debug")
	viper.Set("bouncer.apiKey", key)
	viper.Set("bouncer.lapiURL", hostLAPI.String())
	viper.Set("trustedProxies", trustedProxies)
	viper.Set("bouncer.tickerInterval", "1s")
	viper.Set("bouncer.enabled", true)
	viper.Set("waf.enabled", true)
	viper.Set("waf.apiKey", key)
	viper.Set("waf.appsecURL", appsecURL.String())

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
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/testing",
							":authority": "my-host.com",
							":scheme":    "http",
							"User-Agent": "test-agent",
						},
						Protocol: "HTTP/1.1",
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
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/testing",
							":authority": "my-host.com",
							":scheme":    "http",
							"User-Agent": "test-agent",
						},
						Protocol: "HTTP/1.1",
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
							":method":         "GET",
							":path":           "/testing",
							":authority":      "my-host.com",
							":scheme":         "http",
							"User-Agent":      "test-agent",
						},
						Protocol: "HTTP/1.1",
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
							":method":         "GET",
							":path":           "/testing",
							":authority":      "my-host.com",
							"User-Agent":      "test-agent",
						},
						Protocol: "HTTP/1.1",
					},
				},
			},
		}

		_, _, err = lapiContainer.Exec(t.Context(), []string{
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

	t.Run("trigger inline", func(t *testing.T) {
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
							":method":         "GET",
							":path":           "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl",
							":authority":      "my-host.com",
							"User-Agent":      "test-agent",
						},
						Protocol: "HTTP/1.1",
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
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
