//go:build functional

package functional

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

func marshalProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()

	b, err := proto.Marshal(msg)
	require.NoError(t, err)

	return b
}

func newTestViper() *viper.Viper {
	v := 	config.GetViper("")
	v.Set("server.logLevel", "debug")
	v.Set("templates.showDeniedPage", false)
	return v
}

func wantAllowedResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: 0,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{},
	}
}

func wantForbiddenResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(envoy_type.StatusCode_Forbidden),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Forbidden,
				},
			},
		},
	}
}

func wantRedirectResponse(challengeToken string) *auth.CheckResponse {
	redirectParams := make(url.Values)
	redirectParams.Set("challengeToken", challengeToken)

	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(envoy_type.StatusCode_Found),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Location",
							Value: "http://localhost/captcha/challenge?" + redirectParams.Encode(),
						},
					},
				},
			},
		},
	}
}

const (
	agentUser = "appsec-agent"
	agentPass = "appsec-pass"
)

type credFile struct {
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	URL      string `yaml:"url"`
}

type testEnv struct {
	image            string
	network          string
	lapi             testcontainers.Container
	appsecBan        testcontainers.Container
	appsecCaptcha    testcontainers.Container
	lapiURL          string
	appsecBanURL     string
	appsecCaptchaURL string
	apiKey           string
}

func setupEnv(t *testing.T, image string) *testEnv {
	t.Helper()

	net, err := network.New(t.Context(), network.WithDriver("bridge"))
	require.NoError(t, err)
	t.Cleanup(func() { net.Remove(context.Background()) })

	lapi := startLAPI(t, image, net.Name)
	hostLAPI := containerURL(t, lapi, "8080", "http")

	key := addBouncer(t, lapi)
	addMachine(t, lapi)
	credsPath := writeAppsecCreds(t, "http://lapi:8080")

	appsecBan := startAppsec(t, image, net.Name, "./configs/appsec-ban.yaml", credsPath)
	appsecCaptcha := startAppsec(t, image, net.Name, "./configs/appsec-captcha.yaml", credsPath)

	appsecBanURL := containerURL(t, appsecBan, "7422", "http")
	appsecCaptchaURL := containerURL(t, appsecCaptcha, "7422", "http")

	return &testEnv{
		image:            image,
		network:          net.Name,
		lapi:             lapi,
		appsecBan:        appsecBan,
		appsecCaptcha:    appsecCaptcha,
		lapiURL:          hostLAPI.String(),
		appsecBanURL:     appsecBanURL.String(),
		appsecCaptchaURL: appsecCaptchaURL.String(),
		apiKey:           key,
	}
}

func startLAPI(t *testing.T, image, netName string) testcontainers.Container {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API":               "false",
			"DISABLE_AGENT":                   "true",
			"DISABLE_ONLINE_API":              "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Networks:       []string{netName},
		NetworkAliases: map[string][]string{netName: {"lapi"}},
		WaitingFor:     wait.ForHTTP("/health").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { c.Terminate(context.Background()) })

	return c
}

func startAppsec(t *testing.T, image, netName, configPath, credsPath string) testcontainers.Container {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        image,
		Networks:     []string{netName},
		ExposedPorts: []string{"7422/tcp", "6060/tcp"},
		Env: map[string]string{
			"LOCAL_API_URL":                   "http://lapi:8080",
			"DISABLE_LOCAL_API":               "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: "./configs/acquis.yaml", ContainerFilePath: "/etc/crowdsec/acquis.yaml", FileMode: 0644},
			{HostFilePath: configPath, ContainerFilePath: "/etc/crowdsec/appsec-configs/appsec-config.yaml", FileMode: 0644},
			{HostFilePath: "./configs/appsec-generic-test.yaml", ContainerFilePath: "/etc/crowdsec/appsec-rules/appsec-generic-test.yaml", FileMode: 0644},
			{HostFilePath: credsPath, ContainerFilePath: "/staging/etc/crowdsec/local_api_credentials.yaml", FileMode: 0644},
		},
		WaitingFor: wait.ForHTTP("/metrics").WithPort("6060/tcp").WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { c.Terminate(context.Background()) })

	return c
}

func containerURL(t *testing.T, c testcontainers.Container, port, scheme string) url.URL {
	t.Helper()

	host, err := c.Host(t.Context())
	require.NoError(t, err)
	mapped, err := c.MappedPort(t.Context(), port)
	require.NoError(t, err)

	return url.URL{Scheme: scheme, Host: host + ":" + mapped.Port()}
}

func addBouncer(t *testing.T, lapi testcontainers.Container) string {
	t.Helper()

	_, out, err := lapi.Exec(t.Context(), []string{"cscli", "bouncers", "add", "testBouncer"})
	require.NoError(t, err)
	b, err := io.ReadAll(out)
	require.NoError(t, err)
	key, err := extractAPIKey(string(b))
	require.NoError(t, err)

	return key
}

func addMachine(t *testing.T, lapi testcontainers.Container) {
	t.Helper()

	_, _, err := lapi.Exec(t.Context(), []string{"cscli", "machines", "add", agentUser, "--password", agentPass, "-f", "/tmp/creds.yaml"})
	require.NoError(t, err)
}

func writeAppsecCreds(t *testing.T, appsecLAPI string) string {
	t.Helper()

	creds := credFile{
		URL:      appsecLAPI,
		Login:    agentUser,
		Password: agentPass,
	}
	b, err := yaml.Marshal(creds)
	require.NoError(t, err)

	tmpFile, err := os.CreateTemp("", "local_api_creds-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.Write(b)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	return tmpFile.Name()
}

func (e *testEnv) exec(t *testing.T, args ...string) {
	t.Helper()

	_, _, err := e.lapi.Exec(t.Context(), args)
	require.NoError(t, err)
}

func (e *testEnv) resetDecisions(t *testing.T) {
	t.Helper()

	e.exec(t, "cscli", "decisions", "delete", "--all")
}

func (e *testEnv) addDecision(t *testing.T, args ...string) {
	t.Helper()

	e.exec(t, append([]string{"cscli", "decisions", "add"}, args...)...)
}

func (e *testEnv) deleteDecision(t *testing.T, args ...string) {
	t.Helper()

	e.exec(t, append([]string{"cscli", "decisions", "delete"}, args...)...)
}

func waitForServer(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within %v: %v", addr, timeout, lastErr)
}

func waitForDecisionCache(t *testing.T, dc bouncer.DecisionCache, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if dc.IsReady() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("decision cache did not become ready within %v", timeout)
}

func waitForDecision(t *testing.T, dc bouncer.DecisionCache, ip string, present bool, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		decision, _ := dc.GetDecision(t.Context(), ip)
		if present && decision != nil {
			return
		}
		if !present && decision == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for decision for %s to be present=%v", ip, present)
}

func startServer(t *testing.T, ctx context.Context, srv *server.Server, addr string) func() {
	t.Helper()

	serverCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.ServeDual(serverCtx); err != nil && err != context.Canceled {
			t.Errorf("server error: %v", err)
		}
	}()

	waitForServer(t, addr, 10*time.Second)

	return func() {
		cancel()
		<-done
	}
}
