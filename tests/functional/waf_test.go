//go:build functional

package functional

// import (
// 	"context"
// 	"io"
// 	"log"
// 	"net/url"
// 	"testing"
// 	"time"

// 	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
// 	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
// 	"github.com/kdwils/envoy-proxy-bouncer/cmd"
// 	"github.com/spf13/viper"
// 	"github.com/stretchr/testify/require"
// 	"github.com/testcontainers/testcontainers-go"
// 	"github.com/testcontainers/testcontainers-go/wait"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/credentials/insecure"
// )

// func TestWAF(t *testing.T) {
// 	ctx := t.Context()
// 	lapiReq := testcontainers.ContainerRequest{
// 		Image:        "crowdsecurity/crowdsec:v1.6.8",
// 		ExposedPorts: []string{"8080/tcp"},
// 		Env: map[string]string{
// 			"DISABLE_LOCAL_API": "false",
// 			"DISABLE_AGENT":     "true",
// 			"LOCAL_API_URL":     "http://localhost:8080",
// 		},
// 		WaitingFor: wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
// 	}

// 	lapiContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
// 		ContainerRequest: lapiReq,
// 		Started:          true,
// 	})
// 	if err != nil {
// 		t.Fatalf("failed to start LAPI container: %v", err)
// 	}
// 	defer lapiContainer.Terminate(ctx)

// 	appSecReq := testcontainers.ContainerRequest{
// 		Image:        "crowdsecurity/crowdsec:v1.6.8",
// 		ExposedPorts: []string{"7422/tcp", "6060/tcp"},
// 		Env: map[string]string{
// 			"DISABLE_LOCAL_API": "true",
// 			"DISABLE_AGENT":     "true",
// 			"LAPI_URL":          "http://crowdsec-lapi:8080",
// 		},
// 		Networks: []string{"crowdsec-waf-test-network"},
// 		NetworkAliases: map[string][]string{
// 			"crowdsec-waf-test-network": {"crowdsec-appsec"},
// 		},
// 		Files: []testcontainers.ContainerFile{
// 			{
// 				HostFilePath:      "./configs/acquis.yaml",
// 				ContainerFilePath: "/etc/crowdsec/acquis.yaml",
// 				FileMode:          0644,
// 			},
// 			{
// 				HostFilePath:      "./configs/appsec.yaml",
// 				ContainerFilePath: "/etc/crowdsec/appsec-configs/appsec-config.yaml",
// 				FileMode:          0644,
// 			},
// 		},
// 		WaitingFor: wait.ForHTTP("/metrics").WithPort("6060/tcp").WithStartupTimeout(60 * time.Second),
// 	}

// 	appSecContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
// 		ContainerRequest: appSecReq,
// 		Started:          true,
// 	})
// 	if err != nil {
// 		t.Fatalf("failed to start AppSec container: %v", err)
// 	}
// 	defer appSecContainer.Terminate(ctx)

// 	host, err := lapiContainer.Host(ctx)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	port, err := lapiContainer.MappedPort(ctx, "8080")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	lapiURL := url.URL{
// 		Scheme: "http",
// 		Host:   host + ":" + port.Port(),
// 	}

// 	// Get AppSec container host and port
// 	appSecHost, err := appSecContainer.Host(ctx)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	appSecPort, err := appSecContainer.MappedPort(ctx, "7422")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	appSecURL := url.URL{
// 		Scheme: "http",
// 		Host:   appSecHost + ":" + appSecPort.Port(),
// 	}

// 	// Create API key for bouncer
// 	_, out, err := lapiContainer.Exec(ctx, []string{
// 		"cscli", "bouncers", "add", "testWAFBouncer",
// 	})
// 	if err != nil {
// 		t.Fatalf("failed to exec: %v", err)
// 	}
// 	b, err := io.ReadAll(out)
// 	if err != nil {
// 		t.Fatalf("failed to read output: %v", err)
// 	}

// 	key, err := extractAPIKey(string(b))
// 	if err != nil {
// 		t.Fatalf("failed to extract api key: %v", err)
// 	}

// 	// Configure and start the bouncer service
// 	rootCmd := cmd.ServeCmd.Root()
// 	rootCmd.SetArgs([]string{"serve"})
// 	viper.Set("server.port", 8081)
// 	viper.Set("server.logLevel", "debug")
// 	viper.Set("apiKey", key)
// 	viper.Set("apiURL", lapiURL.String())
// 	viper.Set("waf.apiURL", appSecURL.String())
// 	viper.Set("bouncer.enabled", false)
// 	viper.Set("waf.enabled", true)

// 	go func() {
// 		err = rootCmd.Execute()
// 		if err != nil {
// 			log.Fatalf("failed to execute serve command: %v", err)
// 		}
// 	}()

// 	conn, err := grpc.NewClient("localhost:8081", grpc.WithTransportCredentials(insecure.NewCredentials()))
// 	if err != nil {
// 		t.Fatalf("failed to dial grpc: %v", err)
// 	}
// 	defer conn.Close()

// 	client := auth.NewAuthorizationClient(conn)

// 	t.Run("Test WAF allows clean payload", func(t *testing.T) {
// 		req := &auth.CheckRequest{
// 			Attributes: &auth.AttributeContext{
// 				Source: &auth.AttributeContext_Peer{
// 					Address: &corev3.Address{
// 						Address: &corev3.Address_SocketAddress{
// 							SocketAddress: &corev3.SocketAddress{
// 								Address: "192.168.1.1",
// 							},
// 						},
// 					},
// 				},
// 				Request: &auth.AttributeContext_Request{
// 					Http: &auth.AttributeContext_HttpRequest{
// 						Method: "POST",
// 						Path:   "/api/test",
// 						Body:   "hello world",
// 						Headers: map[string]string{
// 							"Content-Type": "application/json",
// 						},
// 					},
// 				},
// 			},
// 		}
// 		check, err := client.Check(context.TODO(), req)
// 		require.NoError(t, err)
// 		require.NotNil(t, check.HttpResponse)
// 		require.Equal(t, int32(0), check.Status.Code)
// 	})

// 	t.Run("Test WAF blocks XSS payload", func(t *testing.T) {
// 		req := &auth.CheckRequest{
// 			Attributes: &auth.AttributeContext{
// 				Source: &auth.AttributeContext_Peer{
// 					Address: &corev3.Address{
// 						Address: &corev3.Address_SocketAddress{
// 							SocketAddress: &corev3.SocketAddress{
// 								Address: "192.168.1.1",
// 							},
// 						},
// 					},
// 				},
// 				Request: &auth.AttributeContext_Request{
// 					Http: &auth.AttributeContext_HttpRequest{
// 						Method: "POST",
// 						Path:   "/api/test",
// 						Body:   `{"data": "<script>alert('xss')</script>"}`,
// 						Headers: map[string]string{
// 							"Content-Type": "application/json",
// 						},
// 					},
// 				},
// 			},
// 		}
// 		check, err := client.Check(context.TODO(), req)
// 		require.NoError(t, err)
// 		require.NotNil(t, check.HttpResponse)
// 		require.Equal(t, int32(403), check.Status.Code)
// 	})

// 	t.Run("Test WAF blocks SQL injection payload", func(t *testing.T) {
// 		req := &auth.CheckRequest{
// 			Attributes: &auth.AttributeContext{
// 				Source: &auth.AttributeContext_Peer{
// 					Address: &corev3.Address{
// 						Address: &corev3.Address_SocketAddress{
// 							SocketAddress: &corev3.SocketAddress{
// 								Address: "192.168.1.1",
// 							},
// 						},
// 					},
// 				},
// 				Request: &auth.AttributeContext_Request{
// 					Http: &auth.AttributeContext_HttpRequest{
// 						Method: "GET",
// 						Path:   "/api/users?id=1' OR '1'='1",
// 						Headers: map[string]string{
// 							"User-Agent": "TestAgent/1.0",
// 						},
// 					},
// 				},
// 			},
// 		}
// 		check, err := client.Check(context.TODO(), req)
// 		require.NoError(t, err)
// 		require.NotNil(t, check.HttpResponse)
// 		require.Equal(t, int32(403), check.Status.Code)
// 	})

// 	t.Run("Test WAF blocks path traversal payload", func(t *testing.T) {
// 		req := &auth.CheckRequest{
// 			Attributes: &auth.AttributeContext{
// 				Source: &auth.AttributeContext_Peer{
// 					Address: &corev3.Address{
// 						Address: &corev3.Address_SocketAddress{
// 							SocketAddress: &corev3.SocketAddress{
// 								Address: "192.168.1.1",
// 							},
// 						},
// 					},
// 				},
// 				Request: &auth.AttributeContext_Request{
// 					Http: &auth.AttributeContext_HttpRequest{
// 						Method: "GET",
// 						Path:   "/api/file?path=../../../etc/passwd",
// 						Headers: map[string]string{
// 							"User-Agent": "TestAgent/1.0",
// 						},
// 					},
// 				},
// 			},
// 		}
// 		check, err := client.Check(context.TODO(), req)
// 		require.NoError(t, err)
// 		require.NotNil(t, check.HttpResponse)
// 		require.Equal(t, int32(403), check.Status.Code)
// 	})

// 	t.Run("Test WAF blocks command injection payload", func(t *testing.T) {
// 		req := &auth.CheckRequest{
// 			Attributes: &auth.AttributeContext{
// 				Source: &auth.AttributeContext_Peer{
// 					Address: &corev3.Address{
// 						Address: &corev3.Address_SocketAddress{
// 							SocketAddress: &corev3.SocketAddress{
// 								Address: "192.168.1.1",
// 							},
// 						},
// 					},
// 				},
// 				Request: &auth.AttributeContext_Request{
// 					Http: &auth.AttributeContext_HttpRequest{
// 						Method: "POST",
// 						Path:   "/api/execute",
// 						Body:   `{"cmd": "ls; cat /etc/passwd"}`,
// 						Headers: map[string]string{
// 							"Content-Type": "application/json",
// 						},
// 					},
// 				},
// 			},
// 		}
// 		check, err := client.Check(context.TODO(), req)
// 		require.NoError(t, err)
// 		require.NotNil(t, check.HttpResponse)
// 		require.Equal(t, int32(403), check.Status.Code)
// 	})
// }
