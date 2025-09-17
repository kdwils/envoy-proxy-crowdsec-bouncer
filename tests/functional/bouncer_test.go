//go:build functional

package functional

import (
	"context"
	"fmt"
	"io"
	"log"
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
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	bouncermocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

type credFile struct {
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	URL      string `yaml:"url"`
}

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
	
	for k, v := range extraHeaders {
		headers[k] = v
	}
	
	return &auth.AttributeContext_HttpRequest{
		Headers:  headers,
		Protocol: "HTTP/1.1",
	}
}

func TestBouncer(t *testing.T) {
	network, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer network.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.7.0",
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
		Image:        "crowdsecurity/crowdsec:v1.7.0",
		Networks:     []string{network.Name},
		ExposedPorts: []string{"7422/tcp", "6060/tcp"},
		Env: map[string]string{
			"LOCAL_API_URL":                   appsecLAPI.String(),
			"DISABLE_LOCAL_API":               "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./configs/acquis.yaml",
				ContainerFilePath: "/etc/crowdsec/acquis.yaml",
				FileMode:          0644,
			},
			{
				HostFilePath:      "./configs/appsec-ban.yaml",
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

	v := viper.New()
	v.Set("server.port", 8080)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("trustedProxies", trustedProxies)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", key)
	v.Set("waf.appsecURL", appsecURL.String())
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

	if config.Bouncer.Metrics {
		go func() {
			if err := bouncer.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	if config.Captcha.Enabled && bouncer.CaptchaService != nil {
		go bouncer.CaptchaService.StartCleanup(ctx)
	}

	server := server.NewServer(config, bouncer, bouncer.CaptchaService, slogger)

	go func() {
		err := server.ServeDual(ctx)
		if err != nil && err != context.Canceled {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	time.Sleep(5 * time.Second)

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("Test Bouncer non-banned", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

	t.Run("Test banned decision", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("xff with trusted proxy", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("ban decision removed", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

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
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", "my-host.com", map[string]string{
			"x-forwarded-for": "192.168.1.100,10.0.0.1",
		}))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("Test captcha decision with disabled captcha service", func(t *testing.T) {
		req := createCheckRequest("192.168.2.100", createHttpRequest("GET", "/protected", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)

		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})
}

func TestBouncerWithCaptcha(t *testing.T) {
	network, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer network.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.7.0",
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
		"cscli", "decisions", "add", "--type", "captcha", "--value", "192.168.1.100",
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
		Image:        "crowdsecurity/crowdsec:v1.7.0",
		Networks:     []string{network.Name},
		ExposedPorts: []string{"7422/tcp", "6060/tcp"},
		Env: map[string]string{
			"LOCAL_API_URL":                   appsecLAPI.String(),
			"DISABLE_LOCAL_API":               "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./configs/acquis.yaml",
				ContainerFilePath: "/etc/crowdsec/acquis.yaml",
				FileMode:          0644,
			},
			{
				HostFilePath:      "./configs/appsec-captcha.yaml",
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

	v := viper.New()
	v.Set("server.port", 8080)
	v.Set("server.httpPort", 8081)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("trustedProxies", trustedProxies)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", key)
	v.Set("waf.appsecURL", appsecURL.String())
	v.Set("captcha.enabled", true)
	v.Set("captcha.provider", "recaptcha")
	v.Set("captcha.siteKey", "test-site-key")
	v.Set("captcha.secretKey", "test-secret-key")
	v.Set("captcha.url", "http://localhost")

	config, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(config.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testBouncer, err := bouncer.New(config)
	require.NoError(t, err)
	go testBouncer.Sync(ctx)

	mockCaptchaService := bouncermocks.NewMockCaptchaService(ctrl)
	mockCaptchaService.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockCaptchaService.EXPECT().GetProviderName().Return("mock").AnyTimes()
	mockCaptchaService.EXPECT().StartCleanup(gomock.Any()).AnyTimes()

	sessions := make(map[string]*components.CaptchaSession)
	mockCaptchaService.EXPECT().GenerateChallengeURL(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ip, originalURL string) (string, error) {
			sessionID := fmt.Sprintf("session-%s-%d", ip, time.Now().UnixNano())
			sessions[sessionID] = &components.CaptchaSession{
				IP:          ip,
				OriginalURL: originalURL,
				CreatedAt:   time.Now(),
			}
			return fmt.Sprintf("http://localhost/captcha/challenge?session=%s", sessionID), nil
		}).AnyTimes()

	mockCaptchaService.EXPECT().GetSession(gomock.Any()).DoAndReturn(
		func(sessionID string) (*components.CaptchaSession, bool) {
			session, exists := sessions[sessionID]
			return session, exists
		}).AnyTimes()

	mockCaptchaService.EXPECT().RenderChallenge(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(siteKey, callbackURL, redirectURL, sessionID string) (string, error) {
			return fmt.Sprintf(`<html><body><h1>Mock CAPTCHA</h1><p>Session: %s</p><p>Site Key: %s</p></body></html>`, sessionID, siteKey), nil
		}).AnyTimes()

	mockCaptchaService.EXPECT().VerifyResponse(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, req components.VerificationRequest) (*components.VerificationResult, error) {
			success := req.Response == "success"
			return &components.VerificationResult{
				Success: success,
				Message: "Mock verification",
			}, nil
		}).AnyTimes()

	mockCaptchaService.EXPECT().DeleteSession(gomock.Any()).AnyTimes()

	testBouncer.CaptchaService = mockCaptchaService

	if config.Bouncer.Metrics {
		go func() {
			if err := testBouncer.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	if config.Captcha.Enabled && testBouncer.CaptchaService != nil {
		go testBouncer.CaptchaService.StartCleanup(ctx)
	}

	server := server.NewServer(config, testBouncer, testBouncer.CaptchaService, slogger)

	log.Printf("TestBouncerWithCaptcha: Created context, about to start goroutine")
	go func() {
		log.Printf("TestBouncerWithCaptcha: Goroutine starting server")
		err := server.ServeDual(ctx)
		if err != nil && err != context.Canceled {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	time.Sleep(5 * time.Second)

	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	var captchaSessionID string

	t.Run("Test captcha decision triggers captcha challenge", func(t *testing.T) {
		time.Sleep(2 * time.Second)

		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(302), check.Status.Code)

		deniedResponse := check.GetDeniedResponse()
		require.NotNil(t, deniedResponse)
		require.Len(t, deniedResponse.Headers, 1)

		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)
		require.Equal(t, "localhost", locationURL.Host)
		require.Equal(t, "/captcha/challenge", locationURL.Path)
		require.Equal(t, "http", locationURL.Scheme)

		captchaSessionID = locationURL.Query().Get("session")
		require.NotEmpty(t, captchaSessionID)

		session, exists := sessions[captchaSessionID]
		require.True(t, exists)
		require.Equal(t, "192.168.1.100", session.IP)
		require.Equal(t, "http://my-host.com/protected", session.OriginalURL)
	})

	t.Run("Test captcha challenge page served", func(t *testing.T) {
		require.NotEmpty(t, captchaSessionID)

		resp, err := http.Get(fmt.Sprintf("http://localhost:8081/captcha/challenge?session=%s", captchaSessionID))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "Mock CAPTCHA")
		require.Contains(t, string(body), captchaSessionID)
	})

	t.Run("Test WAF trigger captcha flow", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(302), check.Status.Code)

		deniedResponse := check.GetDeniedResponse()
		require.NotNil(t, deniedResponse)
		require.Len(t, deniedResponse.Headers, 1)

		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)
		require.Equal(t, "localhost", locationURL.Host)
		require.Equal(t, "/captcha/challenge", locationURL.Path)
		require.Equal(t, "http", locationURL.Scheme)

		sessionID := locationURL.Query().Get("session")
		require.NotEmpty(t, sessionID)

		session, exists := sessions[sessionID]
		require.True(t, exists)
		require.Equal(t, "192.168.1.1", session.IP)
		require.Equal(t, "http://my-host.com/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", session.OriginalURL)
	})

	t.Run("Test non-captcha decision allows through", func(t *testing.T) {
		req := createCheckRequest("192.168.1.200", createHttpRequest("GET", "/testing", "my-host.com", nil))

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
