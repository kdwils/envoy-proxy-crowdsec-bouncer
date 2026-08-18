//go:build functional

package functional

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type tlsCerts struct {
	caPath         string
	serverCertPath string
	serverKeyPath  string
	clientCertPath string
	clientKeyPath  string
}

func testBouncerTLS(t *testing.T, env *testEnv) {
	certs := generateTLSTestCerts(t)

	lapiReq := testcontainers.ContainerRequest{
		Image:        env.image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API":               "false",
			"DISABLE_AGENT":                   "true",
			"DISABLE_ONLINE_API":              "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Networks: []string{env.network},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: certs.serverCertPath, ContainerFilePath: "/etc/crowdsec/ssl/server.crt", FileMode: 0644},
			{HostFilePath: certs.serverKeyPath, ContainerFilePath: "/etc/crowdsec/ssl/server.key", FileMode: 0600},
			{HostFilePath: certs.caPath, ContainerFilePath: "/etc/crowdsec/ssl/ca.crt", FileMode: 0644},
			{HostFilePath: "./configs/lapi-tls.yaml", ContainerFilePath: "/etc/crowdsec/config.yaml.local", FileMode: 0644},
			{HostFilePath: "./configs/local_api_credentials.yaml.local", ContainerFilePath: "/etc/crowdsec/local_api_credentials.yaml.local", FileMode: 0644},
		},
		WaitingFor: wait.ForHTTP("/health").WithPort("8080/tcp").
			WithTLS(true, &tls.Config{InsecureSkipVerify: true}).
			WithStartupTimeout(30 * time.Second),
	}

	lapiContainer, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: lapiReq,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { lapiContainer.Terminate(t.Context()) })

	lapiHost, err := lapiContainer.Host(t.Context())
	require.NoError(t, err)
	lapiPort, err := lapiContainer.MappedPort(t.Context(), "8080")
	require.NoError(t, err)

	hostLAPI := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%s", lapiHost, lapiPort.Port()),
	}

	_, _, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "decisions", "add", "--type", "ban", "--value", "192.168.1.100",
	})
	require.NoError(t, err)

	v := newTestViper()
	v.Set("server.grpcPort", 8082)
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("bouncer.tls.enabled", true)
	v.Set("bouncer.tls.certPath", certs.clientCertPath)
	v.Set("bouncer.tls.keyPath", certs.clientKeyPath)
	v.Set("bouncer.tls.caPath", certs.caPath)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.metrics", true)

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	rec := recorder.NewNoOp()

	b, err := bouncer.New(cfg, rec, http.DefaultClient)
	require.NoError(t, err)

	go b.Sync(ctx)

	if cfg.Bouncer.Metrics {
		go func() {
			if err := b.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	waitForDecision(t, b.DecisionCache, "192.168.1.100", true, 10*time.Second)

	templateStore, err := template.NewStore(template.Config{})
	require.NoError(t, err)

	srv := server.NewServer(cfg, b, b.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, rec, nil)
	stop := startServer(t, ctx, srv, "localhost:8082")
	defer stop()

	conn, err := grpc.NewClient("localhost:8082", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("allows non-banned ip with tls auth", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("blocks banned ip with tls auth", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantForbiddenResponse()), marshalProto(t, check))
	})

	t.Run("ban decision removed with tls auth", func(t *testing.T) {
		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "delete", "-i", "192.168.1.100",
		})
		require.NoError(t, err)

		waitForDecision(t, b.DecisionCache, "192.168.1.100", false, 10*time.Second)

		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		assert.Equal(t, marshalProto(t, wantAllowedResponse()), marshalProto(t, check))
	})

	t.Run("metrics sent to lapi with tls auth", func(t *testing.T) {
		require.NotNil(t, b.MetricsService)

		snapshot := b.MetricsService.GetSnapshot()
		require.NotEmpty(t, snapshot, "expected metrics to be collected")

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		require.Greater(t, bypassMetric.Value, int64(0), "expected bypass count to be non-zero")

		allMetrics := b.MetricsService.Calculate(time.Second)
		err := b.MetricsService.Send(t.Context(), allMetrics)
		require.NoError(t, err, "expected metrics to be sent to LAPI over TLS")
	})
}

func generateTLSTestCerts(t *testing.T) tlsCerts {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPath := writeTLSPEMFile(t, "CERTIFICATE", caCertDER)

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	serverCertPath := writeTLSPEMFile(t, "CERTIFICATE", serverCertDER)
	serverKeyPath := writeTLSPEMFile(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "testBouncerTLS", OrganizationalUnit: []string{"bouncer"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPath := writeTLSPEMFile(t, "CERTIFICATE", clientCertDER)
	clientKeyPath := writeTLSPEMFile(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return tlsCerts{
		caPath:         caPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
	}
}

func writeTLSPEMFile(t *testing.T, pemType string, data []byte) string {
	f, err := os.CreateTemp("", "*.pem")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })

	err = pem.Encode(f, &pem.Block{Type: pemType, Bytes: data})
	require.NoError(t, err)
	require.NoError(t, f.Close())

	return f.Name()
}
