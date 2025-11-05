//go:build functional

package functional

import (
	"context"
	"fmt"
	"io"
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
	componentmocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
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
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

func TestJWTCompleteVerificationFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	network, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer network.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        "crowdsecurity/crowdsec:v1.7.3",
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
		"cscli", "decisions", "add", "--type", "captcha", "--value", "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("failed to add captcha decision: %v", err)
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
		Image:        "crowdsecurity/crowdsec:v1.7.3",
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
	v.Set("captcha.cookieDomain", ".kyledev.co")
	v.Set("captcha.secureCookie", false)
	v.Set("captcha.challengeDuration", "5m")
	v.Set("captcha.sessionDuration", "1h")

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	decisionCache, err := components.NewDecisionCache(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, cfg.Bouncer.TickerInterval, nil)
	require.NoError(t, err)

	waf := components.NewWAF(cfg.WAF.AppSecURL, cfg.WAF.ApiKey, http.DefaultClient)

	mockProvider := componentmocks.NewMockCaptchaProvider(ctrl)
	mockProvider.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), "success", gomock.Any()).Return(true, nil).AnyTimes()
	mockProvider.EXPECT().Verify(gomock.Any(), gomock.Not("success"), gomock.Any()).Return(false, nil).AnyTimes()

	go decisionCache.Sync(ctx)

	t.Run("Complete JWT verification flow with cookie bypass", func(t *testing.T) {
		captchaService, err := components.NewCaptchaService(cfg.Captcha, http.DefaultClient)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer := &bouncer.Bouncer{
			DecisionCache:  decisionCache,
			WAF:            waf,
			CaptchaService: captchaService,
		}

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, templateStore, slogger)

		testCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			err := srv.ServeDual(testCtx)
			if err != nil && err != context.Canceled {
				t.Logf("server error: %v", err)
			}
		}()

		time.Sleep(2 * time.Second)

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		testIP := "127.0.0.1"

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

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

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://127.0.0.1:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)

		verificationCookie := getCookie(resp, "captcha_verified")
		require.NotNil(t, verificationCookie)
		require.NotEmpty(t, verificationCookie.Value)

		req2 := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
							"cookie":     fmt.Sprintf("captcha_verified=%s", verificationCookie.Value),
						},
					},
				},
			},
		}

		check2, err := client.Check(context.TODO(), req2)
		require.NoError(t, err)
		require.NotNil(t, check2.HttpResponse)
		assert.Equal(t, int32(0), check2.Status.Code)
	})

	t.Run("Multiple requests with same verification cookie bypass captcha", func(t *testing.T) {
		captchaService, err := components.NewCaptchaService(cfg.Captcha, http.DefaultClient)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer := &bouncer.Bouncer{
			DecisionCache:  decisionCache,
			WAF:            waf,
			CaptchaService: captchaService,
		}

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, templateStore, slogger)

		testCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			err := srv.ServeDual(testCtx)
			if err != nil && err != context.Canceled {
				t.Logf("server error: %v", err)
			}
		}()

		time.Sleep(2 * time.Second)

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		testIP := "127.0.0.1"

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.Equal(t, int32(302), check.Status.Code)

		deniedResponse := check.GetDeniedResponse()
		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)

		sessionID := locationURL.Query().Get("session")

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://127.0.0.1:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		verificationCookie := getCookie(resp, "captcha_verified")
		require.NotNil(t, verificationCookie)

		for i := range 5 {
			reqWithCookie := &auth.CheckRequest{
				Attributes: &auth.AttributeContext{
					Source: &auth.AttributeContext_Peer{
						Address: &corev3.Address{
							Address: &corev3.Address_SocketAddress{
								SocketAddress: &corev3.SocketAddress{Address: testIP},
							},
						},
					},
					Request: &auth.AttributeContext_Request{
						Http: &auth.AttributeContext_HttpRequest{
							Headers: map[string]string{
								":method":    "GET",
								":path":      "/protected",
								":authority": "my-host.com",
								":scheme":    "http",
								"cookie":     fmt.Sprintf("captcha_verified=%s", verificationCookie.Value),
							},
						},
					},
				},
			}

			checkResult, err := client.Check(context.TODO(), reqWithCookie)
			require.NoError(t, err)
			assert.Equal(t, int32(0), checkResult.Status.Code, "Request %d should bypass captcha with valid cookie", i+1)
		}
	})

	t.Run("Expired verification token requires new captcha", func(t *testing.T) {
		testIP := "127.0.0.1"

		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "delete", "--ip", testIP,
		})

		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "add", "--type", "captcha", "--value", testIP,
		})
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		cfgShortExpiry := cfg
		cfgShortExpiry.Captcha.SessionDuration = 2 * time.Second

		captchaServiceShort, err := components.NewCaptchaService(cfgShortExpiry.Captcha, http.DefaultClient)
		require.NoError(t, err)
		captchaServiceShort.Provider = mockProvider

		testBouncer := &bouncer.Bouncer{
			DecisionCache:  decisionCache,
			WAF:            waf,
			CaptchaService: captchaServiceShort,
		}

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfgShortExpiry, testBouncer, captchaServiceShort, templateStore, slogger)

		testCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			err := srv.ServeDual(testCtx)
			if err != nil && err != context.Canceled {
				t.Logf("server error: %v", err)
			}
		}()

		time.Sleep(2 * time.Second)

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.Equal(t, int32(302), check.Status.Code)

		deniedResponse := check.GetDeniedResponse()
		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)

		sessionID := locationURL.Query().Get("session")

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://127.0.0.1:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", testIP)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		verificationCookie := getCookie(resp, "captcha_verified")
		require.NotNil(t, verificationCookie)

		reqWithCookie := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: testIP},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
							"cookie":     fmt.Sprintf("captcha_verified=%s", verificationCookie.Value),
						},
					},
				},
			},
		}

		checkWithCookie, err := client.Check(context.TODO(), reqWithCookie)
		require.NoError(t, err)
		assert.Equal(t, int32(0), checkWithCookie.Status.Code)

		time.Sleep(3 * time.Second)

		checkExpired, err := client.Check(context.TODO(), reqWithCookie)
		require.NoError(t, err)
		assert.Equal(t, int32(302), checkExpired.Status.Code)
	})

	t.Run("Expired challenge token rejected", func(t *testing.T) {
		cfgShortChallenge := cfg
		cfgShortChallenge.Captcha.ChallengeDuration = 1 * time.Second

		captchaServiceShort, err := components.NewCaptchaService(cfgShortChallenge.Captcha, http.DefaultClient)
		require.NoError(t, err)
		captchaServiceShort.Provider = mockProvider

		testBouncer := &bouncer.Bouncer{
			DecisionCache:  decisionCache,
			WAF:            waf,
			CaptchaService: captchaServiceShort,
		}

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfgShortChallenge, testBouncer, captchaServiceShort, templateStore, slogger)

		testCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			err := srv.ServeDual(testCtx)
			if err != nil && err != context.Canceled {
				t.Logf("server error: %v", err)
			}
		}()

		time.Sleep(2 * time.Second)

		session, err := captchaServiceShort.CreateSession("127.0.0.1", "http://example.com/protected", "")
		require.NoError(t, err)
		require.NotNil(t, session)

		retrievedSession, exists := captchaServiceShort.GetSession(session.ID)
		require.True(t, exists)
		require.NotNil(t, retrievedSession)

		time.Sleep(2 * time.Second)

		expiredSession, exists := captchaServiceShort.GetSession(session.ID)
		assert.False(t, exists)
		assert.Nil(t, expiredSession)
	})

	t.Run("IP binding enforced on verification token", func(t *testing.T) {
		captchaService, err := components.NewCaptchaService(cfg.Captcha, http.DefaultClient)
		require.NoError(t, err)
		captchaService.Provider = mockProvider

		testBouncer := &bouncer.Bouncer{
			DecisionCache:  decisionCache,
			WAF:            waf,
			CaptchaService: captchaService,
		}

		templateStore, err := template.NewStore(template.Config{})
		require.NoError(t, err)

		srv := server.NewServer(cfg, testBouncer, captchaService, templateStore, slogger)

		testCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go func() {
			err := srv.ServeDual(testCtx)
			if err != nil && err != context.Canceled {
				t.Logf("server error: %v", err)
			}
		}()

		time.Sleep(2 * time.Second)

		conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()

		client := auth.NewAuthorizationClient(conn)

		ipA := "127.0.0.1"
		ipB := "192.168.5.5"

		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "add", "--type", "captcha", "--value", ipA,
		})
		require.NoError(t, err)

		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "add", "--type", "captcha", "--value", ipB,
		})
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		reqA := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: ipA},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
						},
					},
				},
			},
		}

		checkA, err := client.Check(context.TODO(), reqA)
		require.NoError(t, err)
		require.Equal(t, int32(302), checkA.Status.Code)

		deniedResponse := checkA.GetDeniedResponse()
		locationHeader := deniedResponse.Headers[0].Header.Value
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)

		sessionID := locationURL.Query().Get("session")

		form := url.Values{}
		form.Add("session", sessionID)
		form.Add("g-recaptcha-response", "success")

		verifyURL := "http://127.0.0.1:8081/captcha/verify"
		httpReq, err := http.NewRequest("POST", verifyURL, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("X-Forwarded-For", ipA)

		httpClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		verificationCookie := getCookie(resp, "captcha_verified")
		require.NotNil(t, verificationCookie)

		reqB := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{Address: ipB},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method":    "GET",
							":path":      "/protected",
							":authority": "my-host.com",
							":scheme":    "http",
							"cookie":     fmt.Sprintf("captcha_verified=%s", verificationCookie.Value),
						},
					},
				},
			},
		}

		checkB, err := client.Check(context.TODO(), reqB)
		require.NoError(t, err)
		assert.Equal(t, int32(302), checkB.Status.Code)
	})
}

func getCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
