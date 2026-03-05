package crowdsec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/kdwils/envoy-proxy-bouncer/config"
)

func loadCACertPool(caPath string) (*x509.CertPool, error) {
	cp, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system CA certificates: %w", err)
	}
	if cp == nil {
		cp = x509.NewCertPool()
	}
	if caPath == "" {
		return cp, nil
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA certificate '%s': %w", caPath, err)
	}
	cp.AppendCertsFromPEM(caCert)
	return cp, nil
}

func buildCertClient(certPath, keyPath, caPath string, insecureSkipVerify bool) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load certificate '%s' and key '%s': %w", certPath, keyPath, err)
	}
	caCertPool, err := loadCACertPool(caPath)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}, nil
}

func NewClient(cfg config.Bouncer, userAgent string) (*apiclient.ApiClient, error) {
	if cfg.ApiKey == "" && cfg.TLS.CertPath == "" && cfg.TLS.KeyPath == "" {
		return nil, errors.New("no API key nor certificate provided")
	}

	if cfg.ApiKey != "" && (cfg.TLS.CertPath != "" || cfg.TLS.KeyPath != "") {
		return nil, errors.New("cannot use both API key and certificate auth")
	}

	if cfg.LAPIURL == "" {
		return nil, errors.New("LAPI URL is required")
	}

	apiURL := cfg.LAPIURL
	if apiURL[len(apiURL)-1] != '/' {
		apiURL += "/"
	}

	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}

	if cfg.ApiKey != "" {
		transport := &apiclient.APIKeyTransport{APIKey: cfg.ApiKey}
		return apiclient.NewDefaultClient(parsedURL, "v1", userAgent, transport.Client())
	}

	client, err := buildCertClient(cfg.TLS.CertPath, cfg.TLS.KeyPath, cfg.TLS.CAPath, cfg.TLS.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return apiclient.NewDefaultClient(parsedURL, "v1", userAgent, client)
}
