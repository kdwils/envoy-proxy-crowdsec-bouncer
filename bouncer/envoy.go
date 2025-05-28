package bouncer

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/version"
)

type EnvoyBouncer struct {
	bouncer LiveBouncerClient
	headers []string
}

func NewEnvoyBouncer(apiKey, apiURL string, headers []string) (Bouncer, error) {
	bouncer, err := newBouncer(apiKey, apiURL)
	if err != nil {
		return nil, err
	}

	b := &EnvoyBouncer{
		bouncer: bouncer,
		headers: headers,
	}

	return b, nil
}

func newBouncer(apiKey, apiURL string) (*csbouncer.LiveBouncer, error) {
	b := &csbouncer.LiveBouncer{
		APIKey:    apiKey,
		APIUrl:    apiURL,
		UserAgent: "envoy-gateway-bouncer/" + version.Version,
	}

	err := b.Init()
	return b, err
}

func (b *EnvoyBouncer) Bounce(r *http.Request) (bool, error) {
	if r == nil {
		return false, errors.New("nil request")
	}

	ip := b.getRequestIP(r)
	if ip == "" {
		return false, errors.New("no ip found")
	}

	decisions, err := b.getDecision(ip)
	if err != nil {
		return false, err
	}
	if decisions == nil {
		return false, nil
	}

	for _, decision := range *decisions {
		if decision.Value == nil || decision.Type == nil {
			continue
		}

		if *decision.Value == ip && *decision.Type == "ban" {
			return true, nil
		}
	}

	return false, nil
}

func (b *EnvoyBouncer) getRequestIP(r *http.Request) string {
	for _, header := range b.headers {
		ip := b.getIPFromHeader(r, header)
		if ip != "" {
			return ip
		}
	}

	ip := r.RemoteAddr
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}

	return host
}

func (b *EnvoyBouncer) getIPFromHeader(r *http.Request, header string) string {
	ip := r.Header.Get(header)
	if ip == "" {
		return ""
	}

	if header == "X-Forwarded-For" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	return ip
}

func (b *EnvoyBouncer) getDecision(ip string) (*models.GetDecisionsResponse, error) {
	if b.bouncer == nil {
		return nil, errors.New("bouncer not initialized")
	}

	return b.bouncer.Get(ip)
}
