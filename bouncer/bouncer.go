package bouncer

import (
	"errors"
	"net"
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

func (b *EnvoyBouncer) Bounce(ip string, headers map[string]string) (bool, error) {
	if ip == "" {
		return false, errors.New("no ip found")
	}

	if xff, ok := headers["x-forwarded-for"]; ok {
		if len(xff) > maxHeaderLength {
			return false, errors.New("header too big")
		}
		ips := strings.Split(xff, ",")
		if len(ips) > maxIPs {
			return false, errors.New("too many ips in chain")
		}

		for i := len(ips) - 1; i >= 0; i-- {
			parsedIP := strings.TrimSpace(ips[i])
			if !b.isTrustedProxy(parsedIP) && isValidIP(parsedIP) {
				ip = parsedIP
				break
			}
		}
	}

	if !isValidIP(ip) {
		return false, errors.New("invalid ip address")
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

		if *decision.Value == ip && strings.EqualFold(*decision.Type, "ban") {
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

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}
