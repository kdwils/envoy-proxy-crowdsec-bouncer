package crowdsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Run("returns error when no auth provided", func(t *testing.T) {
		cfg := config.Bouncer{LAPIURL: "http://localhost:8080"}
		_, err := NewClient(cfg, "test-agent")
		require.Error(t, err)
		assert.Equal(t, "no API key nor certificate provided", err.Error())
	})

	t.Run("returns error when both api key and cert path provided", func(t *testing.T) {
		cfg := config.Bouncer{
			ApiKey:  "test-key",
			LAPIURL: "http://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: "/path/to/cert", KeyPath: "/path/to/key"},
		}
		_, err := NewClient(cfg, "test-agent")
		require.Error(t, err)
		assert.Equal(t, "cannot use both API key and certificate auth", err.Error())
	})

	t.Run("creates client with api key", func(t *testing.T) {
		cfg := config.Bouncer{ApiKey: "test-key", LAPIURL: "http://localhost:8080"}
		client, err := NewClient(cfg, "test-agent")
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("returns error with invalid lapi url", func(t *testing.T) {
		cfg := config.Bouncer{ApiKey: "test-key", LAPIURL: "://invalid-url"}
		_, err := NewClient(cfg, "test-agent")
		require.Error(t, err)
	})

	t.Run("returns error with missing cert files", func(t *testing.T) {
		cfg := config.Bouncer{
			LAPIURL: "https://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: "/nonexistent/cert.pem", KeyPath: "/nonexistent/key.pem"},
		}
		_, err := NewClient(cfg, "test-agent")
		require.Error(t, err)
	})

	t.Run("creates client with tls cert auth", func(t *testing.T) {
		certPath, keyPath, _ := generateTestClientCert(t)
		cfg := config.Bouncer{
			LAPIURL: "https://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: certPath, KeyPath: keyPath},
		}
		client, err := NewClient(cfg, "test-agent")
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("creates client with tls cert auth and custom ca", func(t *testing.T) {
		certPath, keyPath, caPath := generateTestClientCert(t)
		cfg := config.Bouncer{
			LAPIURL: "https://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: certPath, KeyPath: keyPath, CAPath: caPath},
		}
		client, err := NewClient(cfg, "test-agent")
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("returns error when ca cert file does not exist", func(t *testing.T) {
		certPath, keyPath, _ := generateTestClientCert(t)
		cfg := config.Bouncer{
			LAPIURL: "https://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: certPath, KeyPath: keyPath, CAPath: "/nonexistent/ca.pem"},
		}
		_, err := NewClient(cfg, "test-agent")
		require.Error(t, err)
	})

	t.Run("creates client with tls cert auth and insecure skip verify", func(t *testing.T) {
		certPath, keyPath, _ := generateTestClientCert(t)
		cfg := config.Bouncer{
			LAPIURL: "https://localhost:8080",
			TLS:     config.BouncerTLS{CertPath: certPath, KeyPath: keyPath, InsecureSkipVerify: true},
		}
		client, err := NewClient(cfg, "test-agent")
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestLoadCACertPool(t *testing.T) {
	t.Run("returns system cert pool when ca path is empty", func(t *testing.T) {
		pool, err := loadCACertPool("")
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("returns error when ca file does not exist", func(t *testing.T) {
		_, err := loadCACertPool("/nonexistent/ca.pem")
		require.Error(t, err)
	})

	t.Run("returns pool with ca cert appended", func(t *testing.T) {
		_, _, caPath := generateTestClientCert(t)
		pool, err := loadCACertPool(caPath)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})
}

func generateTestClientCert(t *testing.T) (certPath, keyPath, caPath string) {
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

	caPath = writeTempPEMFile(t, "CERTIFICATE", caCertDER)

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-bouncer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath = writeTempPEMFile(t, "CERTIFICATE", clientCertDER)
	keyPath = writeTempPEMFile(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return certPath, keyPath, caPath
}

func writeTempPEMFile(t *testing.T, pemType string, data []byte) string {
	f, err := os.CreateTemp("", "*.pem")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })

	err = pem.Encode(f, &pem.Block{Type: pemType, Bytes: data})
	require.NoError(t, err)
	require.NoError(t, f.Close())

	return f.Name()
}
