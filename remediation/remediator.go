package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/components"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

//go:generate mockgen -destination=mocks/mock_waf.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation WAF
type WAF interface {
	Inspect(ctx context.Context, req components.AppSecRequest) (components.WAFResponse, error)
}

//go:generate mockgen -destination=mocks/mock_bouncer.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation Bouncer
type Bouncer interface {
	Bounce(ctx context.Context, ip string, headers map[string]string) (bool, error)
	Sync(ctx context.Context) error
	Metrics(ctx context.Context) error
}

//go:generate mockgen -destination=mocks/mock_captcha_service.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/remediation CaptchaService
type CaptchaService interface {
	IsEnabled() bool
	GenerateChallengeURL(ip, originalURL string) (string, error)
	GetProviderName() string
	GetSession(sessionID string) (*components.CaptchaSession, bool)
	VerifyResponse(ctx context.Context, req components.VerificationRequest) (*components.VerificationResult, error)
	DeleteSession(sessionID string)
	StartCleanup(ctx context.Context)
	RenderChallenge(siteKey, callbackURL, redirectURL, sessionID string) (string, error)
}

type Remediator struct {
	Bouncer        Bouncer
	WAF            WAF
	CaptchaService CaptchaService
	TrustedProxies []*net.IPNet
}

// New creates a Remediator from config.Config, instantiating bouncer and WAF only if enabled.
func New(cfg config.Config) (*Remediator, error) {
	trustedProxies, err := parseProxyAddresses(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	var b Bouncer
	if cfg.Bouncer.Enabled {
		b, err = components.NewBouncer(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, cfg.Bouncer.TickerInterval)
		if err != nil {
			return nil, err
		}
	}

	var w WAF
	if cfg.WAF.Enabled {
		w = components.NewWAF(cfg.WAF.AppSecURL, cfg.WAF.ApiKey, http.DefaultClient)
	}

	var c *components.CaptchaService
	if cfg.Captcha.Enabled {
		c, err = components.NewCaptchaService(cfg.Captcha, http.DefaultClient)
		if err != nil {
			return nil, err
		}
	}

	return &Remediator{
		Bouncer:        b,
		WAF:            w,
		CaptchaService: c,
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
	IP         string
	RealIP     string
	Headers    map[string]string
	URL        url.URL
	Method     string
	UserAgent  string
	Body       []byte
	ProtoMajor int
	ProtoMinor int
}

func (e *ParseError) Error() string { return e.Reason }

type CheckedRequest struct {
	IP          string
	Action      string
	Reason      string
	HTTPStatus  int
	RedirectURL string
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

// Check runs bouncer first, then captcha if enabled, then WAF if enabled, and returns the result.
func (r Remediator) Check(ctx context.Context, req *auth.CheckRequest) CheckedRequest {
	parsed := r.ParseCheckRequest(ctx, req)
	ctx = logger.WithContext(ctx, logger.FromContext(ctx).With(slog.String("ip", parsed.RealIP)))

	result := r.checkBouncer(ctx, parsed)
	if result.Action != "allow" {
		return result
	}

	result = r.checkWAF(ctx, parsed)
	switch result.Action {
	case "allow":
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "ok", HTTPStatus: http.StatusOK}
	case "captcha":
		return r.checkCaptcha(ctx, parsed)
	case "deny", "ban", "error":
		return result
	default:
		return CheckedRequest{IP: parsed.RealIP, Action: result.Action, Reason: "unknown action", HTTPStatus: http.StatusInternalServerError}
	}
}

func (r Remediator) checkBouncer(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if r.Bouncer == nil {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "bouncer disabled", HTTPStatus: http.StatusOK}
	}

	logger.Debug("running bouncer")
	logger.Debug("headers", "headers", parsed.Headers)
	bounce, err := r.Bouncer.Bounce(ctx, parsed.RealIP, parsed.Headers)
	if err != nil {
		logger.Error("bouncer error", "error", err)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "bouncer error", HTTPStatus: http.StatusInternalServerError}
	}
	if bounce {
		logger.Debug("bouncing")
		return CheckedRequest{IP: parsed.RealIP, Action: "deny", Reason: "bouncer", HTTPStatus: http.StatusForbidden}
	}
	return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "bouncer passed", HTTPStatus: http.StatusOK}
}

func (r Remediator) checkCaptcha(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if r.CaptchaService == nil || !r.CaptchaService.IsEnabled() {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "captcha disabled", HTTPStatus: http.StatusOK}
	}

	logger.Debug("running captcha")
	originalURL := parsed.URL.String()

	challengeURL, err := r.CaptchaService.GenerateChallengeURL(parsed.RealIP, originalURL)
	if err != nil {
		logger.Error("failed to generate captcha challenge", "error", err)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "captcha error", HTTPStatus: http.StatusInternalServerError}
	}

	if challengeURL == "" {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "captcha not required", HTTPStatus: http.StatusOK}
	}

	return CheckedRequest{
		IP:          parsed.RealIP,
		Action:      "captcha",
		Reason:      "captcha required",
		HTTPStatus:  http.StatusFound,
		RedirectURL: challengeURL,
	}
}

func (r Remediator) checkWAF(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if r.WAF == nil {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "waf disabled", HTTPStatus: http.StatusOK}
	}

	logger.Debug("running WAF")
	logger.Debug("headers", "headers", parsed.Headers)

	wafReq := components.AppSecRequest{
		Method:     parsed.Method,
		URL:        parsed.URL,
		Headers:    parsed.Headers,
		Body:       parsed.Body,
		RealIP:     parsed.RealIP,
		ProtoMajor: parsed.ProtoMajor,
		ProtoMinor: parsed.ProtoMinor,
	}

	wafResult, wafErr := r.WAF.Inspect(ctx, wafReq)
	if wafErr != nil {
		logger.Error("waf error", "error", wafErr)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "waf error", HTTPStatus: http.StatusInternalServerError}
	}

	if wafResult.Action != "allow" {
		return CheckedRequest{IP: parsed.RealIP, Action: wafResult.Action, Reason: "waf", HTTPStatus: http.StatusForbidden}
	}

	return CheckedRequest{IP: parsed.RealIP, Action: wafResult.Action, Reason: "ok", HTTPStatus: http.StatusOK}
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

	url := url.URL{
		Scheme: parsedRequest.Headers[":scheme"],
		Host:   parsedRequest.Headers[":authority"],
		Path:   parsedRequest.Headers[":path"],
	}

	parsedRequest.Method = parsedRequest.Headers[":method"]
	parsedRequest.Body = []byte(httpRequest.GetBody())
	parsedRequest.UserAgent = parsedRequest.Headers["user-agent"]

	if proto := httpRequest.GetProtocol(); proto != "" {
		maj, min := parseHTTPVersion(proto)
		parsedRequest.ProtoMajor = maj
		parsedRequest.ProtoMinor = min
	}

	parsedRequest.URL = url

	return parsedRequest
}

// parseHTTPVersion converts strings like "HTTP/1.1" or "HTTP/2" to (1,1) or (2,0).
func parseHTTPVersion(proto string) (int, int) {
	proto = strings.TrimSpace(proto)
	version, ok := strings.CutPrefix(proto, "HTTP/")
	if !ok {

		return 0, 0
	}

	parts := strings.SplitN(version, ".", 2)
	maj := 0
	min := 0
	if len(parts) > 0 {
		if v, err := strconv.Atoi(parts[0]); err == nil {
			maj = v
		}
	}
	if len(parts) == 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			min = v
		}
	}

	return maj, min
}
