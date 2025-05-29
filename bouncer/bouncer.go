package bouncer

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"slices"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/version"
)

const (
	maxHeaderLength = 1024
	maxIPs          = 20
)

var validHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"True-Client-IP",
}

type EnvoyBouncer struct {
	bouncer        LiveBouncerClient
	headers        []string
	trustedProxies []string
}

func NewEnvoyBouncer(apiKey, apiURL string, trustedProxies []string) (Bouncer, error) {
	bouncer, err := newBouncer(apiKey, apiURL)
	if err != nil {
		return nil, err
	}

	b := &EnvoyBouncer{
		bouncer:        bouncer,
		headers:        validHeaders,
		trustedProxies: trustedProxies,
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

		if *decision.Value != ip {
			continue
		}

		if strings.EqualFold(*decision.Type, "ban") {
			return true, nil
		}
	}

	return false, nil
}

func (b *EnvoyBouncer) getDecision(ip string) (*models.GetDecisionsResponse, error) {
	if b.bouncer == nil {
		return nil, errors.New("bouncer not initialized")
	}

	return b.bouncer.Get(ip)
}

func (b *EnvoyBouncer) isTrustedProxy(ip string) bool {
	return slices.Contains(b.trustedProxies, ip)
}

func (b *EnvoyBouncer) getRequestIP(r *http.Request) string {
	for _, header := range b.headers {
		ip := b.getIPFromHeader(r, header)
		if ip != "" {
			return ip
		}
	}

	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		if strings.HasPrefix(ip, "[") {
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = strings.Trim(host, "[]")
			}
		}
		if isValidIP(ip) {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}

	if isValidIP(ip) {
		return ip
	}

	return ""
}

func (b *EnvoyBouncer) getIPFromHeader(r *http.Request, header string) string {
	ip := r.Header.Get(header)
	if ip == "" || len(ip) > maxHeaderLength {
		return ""
	}

	if strings.EqualFold(header, "X-Forwarded-For") {
		ips := strings.Split(ip, ",")
		if len(ips) > maxIPs {
			return ""
		}

		for i := len(ips) - 1; i >= 0; i-- {
			ip = strings.TrimSpace(ips[i])
			if !b.isTrustedProxy(ip) && isValidIP(ip) {
				return ip
			}
		}
		return ""
	}

	if isValidIP(ip) {
		return ip
	}

	return ""
}

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}
