package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/components"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/version"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

//go:generate mockgen -destination=mocks/mock_waf.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation WAF
type WAF interface {
	Inspect(ctx context.Context, req *http.Request, realIP string) (components.WAFResponse, error)
}

//go:generate mockgen -destination=mocks/mock_bouncer.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation Bouncer
type Bouncer interface {
	Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error)
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

type Remediator struct {
	Bouncer        Bouncer
	WAF            WAF
	TrustedProxies []*net.IPNet
}

// New creates a Remediator from config.Config, instantiating bouncer and WAF only if enabled.
func New(cfg config.Config) (*Remediator, error) {
	trustedProxies, err := parseProxyAddresses(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}

	userAgent := "envoy-proxy-bouncer/" + version.Version

	var b Bouncer
	if cfg.Bouncer.Enabled {
		b, err = components.NewBouncer(cfg.ApiKey, cfg.ApiURL, cfg.Bouncer.TickerInterval)
		if err != nil {
			return nil, err
		}
	}

	var w WAF
	if cfg.WAF.Enabled {
		apiClient, err := crowdsec.NewClient(cfg.ApiKey, cfg.ApiURL, userAgent)
		if err != nil {
			return nil, err
		}

		w = components.NewWAF(cfg.ApiKey, cfg.ApiURL, apiClient)
	}

	return &Remediator{
		Bouncer:        b,
		WAF:            w,
		TrustedProxies: trustedProxies,
	}, nil
}

func (r *Remediator) Sync(ctx context.Context) error {
	if r.Bouncer == nil {
		return errors.New("bouncer not initialized")
	}
	return r.Bouncer.Sync(ctx)
}

func (r *Remediator) Metrics(ctx context.Context) error {
	if r.Bouncer == nil {
		return errors.New("bouncer not initialized")
	}
	return r.Bouncer.Metrics(ctx)
}

// extractRealIP determines the real client IP from headers and socket address, matching bouncer logic.
// Headers are checked case-insensitively to handle both normalized and original casing.
func extractRealIP(ip string, headers map[string]string, trustedProxies []*net.IPNet) string {
	// Look for X-Forwarded-For header (case-insensitive)
	for k, v := range headers {
		if strings.EqualFold(k, "x-forwarded-for") && v != "" {
			ips := strings.Split(v, ",")
			if len(ips) > 20 {
				ips = ips[len(ips)-20:]
			}
			for i := len(ips) - 1; i >= 0; i-- {
				parsedIP := strings.TrimSpace(ips[i])
				if !isTrustedProxy(parsedIP, trustedProxies) && isValidIP(parsedIP) {
					return parsedIP
				}
			}
		}
	}

	// Look for X-Real-IP header (case-insensitive)
	for k, v := range headers {
		if strings.EqualFold(k, "x-real-ip") && v != "" && isValidIP(v) {
			return v
		}
	}

	return ip
}

// isTrustedProxy returns true if the IP is in the trusted proxies list.
func isTrustedProxy(ip string, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, net := range trustedProxies {
		if net.Contains(parsed) {
			return true
		}
	}
	return false
}

// isValidIP returns true if the string is a valid IPv4 or IPv6 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ParseError is returned when parsing the CheckRequest fails.
type ParseError struct{ Reason string }

// ParsedRequest holds the fields extracted from the gRPC CheckRequest for remediation logic.
type ParsedRequest struct {
	IP          string // original socket address
	RealIP      string // extracted real client IP
	Headers     map[string]string
	URI         string
	URL         *url.URL // complete URL with scheme, host, path, and query
	Host        string
	Method      string
	UserAgent   string
	HTTPVersion string
	Body        []byte
}

// ParseError is returned when parsing the CheckRequest fails.

func (e *ParseError) Error() string { return e.Reason }

type CheckedRequest struct {
	Action     string
	Reason     string
	HTTPStatus int
}

func parseProxyAddresses(trustedProxies []string) ([]*net.IPNet, error) {
	ipNets := make([]*net.IPNet, 0, len(trustedProxies))
	for _, proxy := range trustedProxies {
		if !strings.Contains(proxy, "/") {
			if strings.Contains(proxy, ":") {
				proxy = proxy + "/128"
			} else {
				proxy = proxy + "/32"
			}
		}

		_, ipNet, err := net.ParseCIDR(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy address %s: %v", proxy, err)
		}
		ipNets = append(ipNets, ipNet)
	}

	return ipNets, nil
}

// Check runs bouncer first, then WAF if enabled, and returns the result.
// Check parses the gRPC CheckRequest, runs bouncer first, then WAF if enabled, and returns the result.
func (r Remediator) Check(ctx context.Context, req *auth.CheckRequest) CheckedRequest {
	logger := logger.FromContext(ctx).With(slog.String("component", "remediator"), slog.String("method", "check"))
	parsed := r.ParseCheckRequest(ctx, req)

	logger = logger.With(slog.String("ip", parsed.RealIP))
	logger.Info("checking ip")
	if r.Bouncer != nil {
		bounce, err := r.Bouncer.Bounce(ctx, parsed.RealIP, parsed.Headers)
		if err != nil {
			logger.Error("bouncer error", "error", err)
			return CheckedRequest{Action: "error", Reason: "bouncer error", HTTPStatus: http.StatusInternalServerError}
		}
		if bounce {
			logger.Info("bouncing")
			return CheckedRequest{Action: "deny", Reason: "bouncer", HTTPStatus: http.StatusForbidden}
		}
	}

	if r.WAF != nil {
		logger.Info("running WAF inspection", "uri", parsed.URI, "host", parsed.Host, "method", parsed.Method, "userAgent", parsed.UserAgent, "httpVersion", parsed.HTTPVersion)

		// Build http.Request for WAF inspection using the pre-built URL
		var bodyReader io.Reader
		if len(parsed.Body) > 0 {
			bodyReader = bytes.NewReader(parsed.Body)
		}

		httpReq, err := http.NewRequest(parsed.Method, parsed.URL.String(), bodyReader)
		if err != nil {
			logger.Error("failed to build http.Request for WAF", "error", err)
			return CheckedRequest{Action: "error", Reason: "waf request build error", HTTPStatus: http.StatusInternalServerError}
		}

		// Set headers from parsed request
		httpReq.Header = make(http.Header)
		for k, v := range parsed.Headers {
			httpReq.Header.Set(k, v)
		}

		// Set host and real IP
		httpReq.Host = parsed.Host
		httpReq.Header.Set("X-Real-IP", parsed.RealIP)
		httpReq.RemoteAddr = parsed.RealIP

		wafResult, wafErr := r.WAF.Inspect(ctx, httpReq, parsed.RealIP)
		if wafErr != nil {
			logger.Error("waf error", "error", wafErr)
			return CheckedRequest{Action: "error", Reason: "waf error", HTTPStatus: http.StatusInternalServerError}
		}

		logger.Info("result", "action", wafResult.Action)
		if wafResult.Action != "allow" {
			return CheckedRequest{Action: wafResult.Action, Reason: "waf", HTTPStatus: http.StatusForbidden}
		}
	}

	return CheckedRequest{Action: "allow", Reason: "ok", HTTPStatus: http.StatusOK}
}

// ParseCheckRequest extracts relevant fields from the gRPC CheckRequest for remediation.
func (r *Remediator) ParseCheckRequest(ctx context.Context, req *auth.CheckRequest) *ParsedRequest {
	parsedRequest := &ParsedRequest{Headers: make(map[string]string)}
	if req == nil {
		return parsedRequest
	}

	attrs := req.GetAttributes()
	if attrs == nil {
		return parsedRequest
	}

	if src := attrs.GetSource(); src != nil {
		if addr := src.GetAddress(); addr != nil {
			if socketAddr := addr.GetSocketAddress(); socketAddr != nil {
				parsedRequest.IP = socketAddr.GetAddress()
				parsedRequest.RealIP = socketAddr.GetAddress()
			}
		}
	}

	request := attrs.GetRequest()
	if request == nil {
		return parsedRequest
	}

	httpRequest := request.GetHttp()
	if httpRequest == nil {
		return parsedRequest
	}

	if httpRequest.Headers != nil {
		for k, v := range httpRequest.Headers {
			parsedRequest.Headers[strings.ToLower(k)] = v
		}
	}

	parsedRequest.RealIP = extractRealIP(parsedRequest.IP, parsedRequest.Headers, r.TrustedProxies)

	parsedRequest.URI = httpRequest.GetPath()
	parsedRequest.Host = httpRequest.GetHost()
	parsedRequest.Method = httpRequest.GetMethod()
	parsedRequest.HTTPVersion = httpRequest.GetProtocol()
	parsedRequest.Body = []byte(httpRequest.GetBody())

	for _, key := range []string{"user-agent", "User-Agent"} {
		if ua := parsedRequest.Headers[strings.ToLower(key)]; ua != "" {
			parsedRequest.UserAgent = ua
			break
		}
	}

	scheme := "http"
	if strings.Contains(parsedRequest.HTTPVersion, "2") || parsedRequest.Headers["x-forwarded-proto"] == "https" {
		scheme = "https"
	}

	parsedRequest.URL = &url.URL{
		Scheme: scheme,
		Host:   parsedRequest.Host,
		Path:   parsedRequest.URI,
	}

	return parsedRequest
}
