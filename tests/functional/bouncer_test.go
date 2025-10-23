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
	"github.com/kdwils/envoy-proxy-bouncer/template"
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
	v.Set("server.grpcPort", 8080)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("trustedProxies", trustedProxies)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", true)
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

		originCounts := bouncer.DecisionCache.GetOriginCounts()
		require.NotEmpty(t, originCounts, "should have active decisions before removal")
		require.Contains(t, originCounts, "cscli", "should have cscli origin")
		require.Equal(t, 1, originCounts["cscli"], "should have 1 decision from cscli origin")

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

	t.Run("Verify metrics after basic scenarios", func(t *testing.T) {
		snapshot := bouncer.MetricsService.GetSnapshot()

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		require.Equal(t, int64(3), bypassMetric.Value)

		banMetric, ok := snapshot["CAPI:ban"]
		require.True(t, ok, "expected CAPI:ban metric to exist")
		require.Equal(t, int64(3), banMetric.Value)

		originCounts := bouncer.DecisionCache.GetOriginCounts()
		require.Empty(t, originCounts, "should have no active decisions after deletion in previous test")
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
	v.Set("server.grpcPort", 8080)
	v.Set("server.httpPort", 8081)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.apiKey", key)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("trustedProxies", trustedProxies)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", true)
	v.Set("waf.enabled", true)
	v.Set("waf.apiKey", key)
	v.Set("waf.appsecURL", appsecURL.String())
	v.Set("captcha.enabled", true)
	v.Set("captcha.provider", "recaptcha")
	v.Set("captcha.siteKey", "test-site-key")
	v.Set("captcha.secretKey", "test-secret-key")
	v.Set("captcha.signingKey", "test-signing-key-for-jwt-sessions")
	v.Set("captcha.callbackURL", "http://localhost")

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
	mockCaptchaService.EXPECT().StartCleanup(gomock.Any()).AnyTimes()

	sessions := make(map[string]*components.CaptchaSession)
	sessionCounter := 0
	mockCaptchaService.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ip, originalURL string) (*components.CaptchaSession, error) {
			sessionCounter++
			sessionID := fmt.Sprintf("test-session-%d", sessionCounter)
			csrfToken := fmt.Sprintf("csrf-token-%d", sessionCounter)
			session := &components.CaptchaSession{
				IP:           ip,
				OriginalURL:  originalURL,
				RedirectURL:  originalURL,
				CreatedAt:    time.Now(),
				ID:           sessionID,
				Provider:     "recaptcha",
				SiteKey:      "test-site-key",
				CallbackURL:  "http://localhost/captcha",
				ChallengeURL: fmt.Sprintf("http://localhost/captcha/challenge?session=%s", sessionID),
				CSRFToken:    csrfToken,
			}
			sessions[sessionID] = session
			return session, nil
		}).AnyTimes()

	mockCaptchaService.EXPECT().GetSession(gomock.Any()).DoAndReturn(
		func(sessionID string) (*components.CaptchaSession, bool) {
			session, exists := sessions[sessionID]
			return session, exists
		}).AnyTimes()

	mockCaptchaService.EXPECT().VerifyResponse(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, sessionID string, req components.VerificationRequest) (*components.VerificationResult, error) {
			success := req.Response == "success"
			if success {
				delete(sessions, sessionID)
			}
			return &components.VerificationResult{
				Success: success,
				Message: "Mock verification",
			}, nil
		}).AnyTimes()

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

	templateStore, err := template.NewStore(template.Config{})
	if err != nil {
		log.Fatalf("failed to create template store: %v", err)
	}

	server := server.NewServer(config, testBouncer, testBouncer.CaptchaService, templateStore, slogger)

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

	t.Run("Test captcha decision triggers captcha challenge and page is served", func(t *testing.T) {
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
		t.Logf("Parsed location URL: %s", locationHeader)
		t.Logf("Extracted session ID: %s", captchaSessionID)
		require.NotEmpty(t, captchaSessionID)

		session, exists := sessions[captchaSessionID]
		require.True(t, exists)
		require.Equal(t, "192.168.1.100", session.IP)
		require.Equal(t, "http://my-host.com/protected", session.OriginalURL)
		require.Equal(t, "http://my-host.com/protected", session.RedirectURL)

		// Test that the captcha challenge page is served correctly
		challengeURL := fmt.Sprintf("http://localhost:8081/captcha/challenge?session=%s", captchaSessionID)
		t.Logf("Making HTTP request to: %s", challengeURL)
		resp, err := http.Get(challengeURL)
		require.NoError(t, err, "Failed to make HTTP request to challenge page")
		defer resp.Body.Close()
		t.Logf("HTTP response status: %d", resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("HTTP response body: %s", string(body))
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "<title>Security Verification</title>")
		require.Contains(t, string(body), "test-site-key")
	})

	t.Run("Test CSRF token validation - invalid token", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected-csrf-test", "my-host.com", nil))

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

		sessionID := locationURL.Query().Get("session")
		require.NotEmpty(t, sessionID)

		session, exists := sessions[sessionID]
		require.True(t, exists)
		require.NotEmpty(t, session.CSRFToken)

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("csrf_token", "invalid-csrf-token")
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		resp, err := http.PostForm(verifyURL, form)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "Invalid CSRF token")
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
		require.Equal(t, "http://my-host.com/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl", session.RedirectURL)
	})

	t.Run("Test non-captcha decision allows through", func(t *testing.T) {
		req := createCheckRequest("192.168.1.200", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

	t.Run("Test invalid redirect URL is rejected", func(t *testing.T) {
		captchaService, err := components.NewCaptchaService(config.Captcha, &http.Client{})
		require.NoError(t, err)

		session, err := captchaService.CreateSession("192.168.1.100", "javascript:alert('xss')")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")

		session, err = captchaService.CreateSession("192.168.1.100", "/relative/path")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")

		session, err = captchaService.CreateSession("192.168.1.100", "ftp://example.com/file")
		require.Error(t, err)
		require.Nil(t, session)
		require.Contains(t, err.Error(), "invalid redirect URL")
	})

	t.Run("Test IP mismatch during verification", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected-ip-test", "my-host.com", nil))

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

		sessionID := locationURL.Query().Get("session")
		require.NotEmpty(t, sessionID)

		session, exists := sessions[sessionID]
		require.True(t, exists)
		require.NotEmpty(t, session.CSRFToken)

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("csrf_token", session.CSRFToken)
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://localhost:8081/captcha/verify"
		httpClient := &http.Client{}
		req2, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req2.Header.Set("X-Forwarded-For", "10.0.0.1")

		resp, err := httpClient.Do(req2)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "IP address mismatch")
	})

	t.Run("Test rate limiting on captcha endpoints", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/protected-ratelimit-test", "my-host.com", nil))

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

		sessionID := locationURL.Query().Get("session")
		require.NotEmpty(t, sessionID)

		challengeURL := "http://localhost:8081/captcha/challenge?session=" + sessionID
		httpClient := &http.Client{}

		successCount := 0
		rateLimitCount := 0

		for range 25 {
			req, err := http.NewRequest("GET", challengeURL, nil)
			require.NoError(t, err)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")

			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				successCount++
			case http.StatusTooManyRequests:
				rateLimitCount++
			}
		}

		require.Greater(t, successCount, 0)
		require.Greater(t, rateLimitCount, 0)
	})

	t.Run("Verify metrics after captcha scenarios", func(t *testing.T) {
		snapshot := testBouncer.MetricsService.GetSnapshot()

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		require.Equal(t, int64(1), bypassMetric.Value)

		captchaMetric, ok := snapshot["CAPI:captcha"]
		require.True(t, ok, "expected CAPI:captcha metric to exist")
		require.Equal(t, int64(5), captchaMetric.Value)

		activeDecisionsFound := false
		for key, metric := range snapshot {
			if metric.Name == "active_decisions" {
				activeDecisionsFound = true
				origin, hasOrigin := metric.Labels["origin"]
				require.True(t, hasOrigin, "active_decisions metric should have origin label")
				require.NotEmpty(t, origin, "active_decisions origin should not be empty")
				require.Equal(t, "ip", metric.Unit)
				require.GreaterOrEqual(t, metric.Value, int64(0), "active_decisions count should be non-negative for key %s", key)
			}
		}
		require.True(t, activeDecisionsFound, "should have active_decisions metrics from decision cache")
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
