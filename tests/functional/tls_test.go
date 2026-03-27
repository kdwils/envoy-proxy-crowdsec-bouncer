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
	"log"
	"log/slog"
	"math/big"
	"net"
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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
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

func TestBouncerWithTLS(t *testing.T) {
	for _, image := range CrowdsecImages {
		t.Run(image, func(t *testing.T) {
			testBouncerWithTLSVersion(t, image)
		})
	}
}

func testBouncerWithTLSVersion(t *testing.T, image string) {
	certs := generateTLSTestCerts(t)

	net, err := network.New(t.Context(), network.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer net.Remove(t.Context())

	lapiReq := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"DISABLE_LOCAL_API":               "false",
			"DISABLE_AGENT":                   "true",
			"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
		},
		Networks:       []string{net.Name},
		NetworkAliases: map[string][]string{net.Name: {"lapi"}},
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
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%s", lapiHost, lapiPort.Port()),
	}

	_, _, err = lapiContainer.Exec(t.Context(), []string{
		"cscli", "decisions", "add", "--type", "ban", "--value", "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("failed to add decision: %v", err)
	}

	v := viper.New()
	v.Set("server.grpcPort", 8082)
	v.Set("server.logLevel", "debug")
	v.Set("bouncer.lapiURL", hostLAPI.String())
	v.Set("bouncer.tls.enabled", true)
	v.Set("bouncer.tls.certPath", certs.clientCertPath)
	v.Set("bouncer.tls.keyPath", certs.clientKeyPath)
	v.Set("bouncer.tls.caPath", certs.caPath)
	v.Set("bouncer.tls.insecureSkipVerify", false)
	v.Set("bouncer.tickerInterval", "1s")
	v.Set("bouncer.enabled", true)
	v.Set("bouncer.metrics", true)
	v.Set("waf.enabled", false)
	v.Set("captcha.enabled", false)

	cfg, err := config.New(v)
	require.NoError(t, err)

	level := logger.LevelFromString(cfg.Server.LogLevel)
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slogger := slog.New(handler)

	ctx := logger.WithContext(t.Context(), slogger)

	recorder := recorder.NewNoOp()

	b, err := bouncer.New(cfg, recorder)
	require.NoError(t, err)

	go b.Sync(ctx)

	if cfg.Bouncer.Metrics {
		go func() {
			if err := b.Metrics(ctx); err != nil {
				slogger.Error("metrics error", "error", err)
			}
		}()
	}

	templateStore, err := template.NewStore(template.Config{})
	if err != nil {
		log.Fatalf("failed to create template store: %v", err)
	}

	srv := server.NewServer(cfg, b, b.CaptchaService, webhook.NewNoopNotifier(), templateStore, slogger, recorder, nil)

	go func() {
		err := srv.ServeDual(ctx)
		if err != nil && err != context.Canceled {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	time.Sleep(5 * time.Second)

	conn, err := grpc.NewClient("localhost:8082", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}
	defer conn.Close()

	client := auth.NewAuthorizationClient(conn)

	t.Run("allows non-banned ip with tls auth", func(t *testing.T) {
		req := createCheckRequest("192.168.1.1", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

	t.Run("blocks banned ip with tls auth", func(t *testing.T) {
		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))

		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(403), check.Status.Code)
	})

	t.Run("ban decision removed with tls auth", func(t *testing.T) {
		_, _, err = lapiContainer.Exec(t.Context(), []string{
			"cscli", "decisions", "delete", "-i", "192.168.1.100",
		})
		if err != nil {
			t.Fatalf("failed to delete decision: %v", err)
		}

		time.Sleep(2 * time.Second)

		req := createCheckRequest("192.168.1.100", createHttpRequest("GET", "/testing", "my-host.com", nil))
		check, err := client.Check(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, check.HttpResponse)
		require.Equal(t, int32(0), check.Status.Code)
	})

	t.Run("metrics sent to lapi with tls auth", func(t *testing.T) {
		require.NotNil(t, b.MetricsService)

		snapshot := b.MetricsService.GetSnapshot()
		require.NotEmpty(t, snapshot, "expected metrics to be collected")

		bypassMetric, ok := snapshot["CAPI:bypass"]
		require.True(t, ok, "expected CAPI:bypass metric to exist")
		require.Greater(t, bypassMetric.Value, int64(0), "expected bypass count to be non-zero")

		allMetrics := b.MetricsService.Calculate(time.Second)
		err := b.MetricsService.Send(context.Background(), allMetrics)
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
