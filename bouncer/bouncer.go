package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/recorder"
	bouncerVersion "github.com/kdwils/envoy-proxy-bouncer/version"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

//go:generate mockgen -destination=mocks/mock_waf.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer WAF
type WAF interface {
	Inspect(ctx context.Context, req components.AppSecRequest) (components.WAFResponse, error)
}

//go:generate mockgen -destination=mocks/mock_decision_cache.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer DecisionCache
type DecisionCache interface {
	GetDecision(ctx context.Context, ip string) (*models.Decision, error)
	Sync(ctx context.Context) error
	Size() int
	GetOriginCounts() map[string]int
	IsReady() bool
}

//go:generate mockgen -destination=mocks/mock_captcha_service.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer CaptchaService
type CaptchaService interface {
	IsEnabled() bool
	RequiresCaptcha(sessionToken string) bool
	CreateSession(ip, originalURL, sessionToken string) (*components.CaptchaSession, error)
	GetSession(challengeToken string) (*components.CaptchaSession, bool)
	VerifyResponse(ctx context.Context, ip, challengeToken, challengeResponse string) (*components.VerificationResult, error)
	CookieName() string
	StartCleanup(ctx context.Context)
}

type Bouncer struct {
	DecisionCache      DecisionCache
	WAF                WAF
	CaptchaService     CaptchaService
	TrustedProxies     []netip.Prefix
	TrustedIPHeader    string
	ExemptIPs          []netip.Prefix
	MetricsService     *crowdsec.MetricsService
	PrometheusRecorder *recorder.Recorder
	remediationMetrics map[string]remediationMetric
	config             config.Config
}

type remediationMetric struct {
	key    string
	name   string
	labels map[string]string
}

func newRemediationMetrics() map[string]remediationMetric {
	return map[string]remediationMetric{
		"allow": {
			key:  "CAPI:bypass",
			name: "processed",
			labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "bypass",
			},
		},
		"ban": {
			key:  "CAPI:ban",
			name: "dropped",
			labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "ban",
			},
		},
		"captcha": {
			key:  "CAPI:captcha",
			name: "dropped",
			labels: map[string]string{
				"origin":      "CAPI",
				"remediation": "captcha",
			},
		},
	}
}

func New(cfg config.Config, recorder *recorder.Recorder, httpClient *http.Client) (*Bouncer, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	trustedProxies, err := parseIPNets(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}

	exemptIPs, err := parseIPNets(cfg.ExemptIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exempt IPs list: %w", err)
	}

	bouncer := &Bouncer{
		TrustedProxies:     trustedProxies,
		TrustedIPHeader:    cfg.TrustedIPHeader,
		ExemptIPs:          exemptIPs,
		PrometheusRecorder: recorder,
		remediationMetrics: newRemediationMetrics(),
		config:             cfg,
	}

	if cfg.Bouncer.Enabled && cfg.Bouncer.Metrics {
		userAgent := "envoy-proxy-crowdsec-bouncer/" + version.Version
		client, err := crowdsec.NewClient(cfg.Bouncer, userAgent, httpClient)
		if err != nil {
			return nil, err
		}

		collector, err := crowdsec.NewMetricsService(crowdsec.MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy-crowdsec-bouncer",
			Version:     bouncerVersion.Version,
		})
		if err != nil {
			return nil, err
		}

		bouncer.MetricsService = collector
	}

	var dc DecisionCache
	if cfg.Bouncer.Enabled {
		dc, err = components.NewDecisionCache(cfg.Bouncer, bouncer.MetricsService, bouncer.PrometheusRecorder)
		if err != nil {
			return nil, err
		}
	}

	var w WAF
	if cfg.WAF.Enabled {
		w, err = components.NewWAF(cfg.WAF.AppSecURL, cfg.WAF.ApiKey, cfg.WAF.HTTPTimeout, httpClient)
		if err != nil {
			return nil, err
		}
	}

	var c *components.CaptchaService
	if cfg.Captcha.Enabled {
		c, err = components.NewCaptchaService(cfg.Captcha, httpClient, recorder)
		if err != nil {
			return nil, err
		}
		bouncer.CaptchaService = c
	}

	bouncer.DecisionCache = dc
	bouncer.WAF = w

	return bouncer, nil
}

func (b *Bouncer) Sync(ctx context.Context) error {
	if b.DecisionCache == nil {
		return errors.New("decision cache not initialized")
	}
	return b.DecisionCache.Sync(ctx)
}

func (b *Bouncer) Metrics(ctx context.Context) error {
	if b.MetricsService == nil {
		return nil
	}
	return b.MetricsService.Run(ctx, b.config.Bouncer.MetricsInterval)
}

func (b *Bouncer) IsReady() bool {
	if !b.config.Bouncer.Enabled {
		return true
	}
	if b.DecisionCache == nil {
		return false
	}
	return b.DecisionCache.IsReady()
}

func (b *Bouncer) recordFinalMetric(result CheckedRequest) {
	b.PrometheusRecorder.IncRequestsTotal(result.Action)

	if b.MetricsService == nil {
		return
	}
	if m, ok := b.remediationMetrics[result.Action]; ok {
		b.MetricsService.Inc(m.key, m.name, "request", m.labels)
	}
}

// ExtractRealIPFromHTTP extracts the real client IP from an HTTP request using trusted proxy logic.
func (b *Bouncer) ExtractRealIPFromHTTP(r *http.Request) string {
	var xForwardedFor, xRealIP, trustedValue string
	for k, v := range r.Header {
		if len(v) == 0 {
			continue
		}
		if b.TrustedIPHeader != "" && strings.EqualFold(k, b.TrustedIPHeader) {
			trustedValue = v[0]
		}
		switch strings.ToLower(k) {
		case "x-forwarded-for":
			xForwardedFor = v[0]
		case "x-real-ip":
			xRealIP = v[0]
		}
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	realIP, _ := ExtractRealIP(host, xForwardedFor, xRealIP, trustedValue, b.TrustedProxies)
	return realIP
}

// ExtractRealIP determines the real client IP from the socket address and the extracted header
// values, matching bouncer logic.
//
// If trustedIPValue is set (the value of the configured trustedIPHeader), it is checked first and,
// if present with a valid IP, returned directly - no X-Forwarded-For parsing or trustedProxies
// matching involved. This is for deployments where an upstream proxy (e.g. an Envoy edge gateway
// with numTrustedProxies configured) has already resolved the real client IP itself and stamped it
// into a single, dedicated header (e.g. X-Envoy-External-Address), so the bouncer doesn't need its
// own external-proxy IP-range allowlist to re-derive the same answer. Falls back to the existing
// X-Forwarded-For/X-Real-IP/trustedProxies logic if the header is unset or absent from the request,
// so this is fully backward compatible.
func ExtractRealIP(ip, xForwardedFor, xRealIP, trustedIPValue string, trustedProxies []netip.Prefix) (string, netip.Addr) {
	if trustedIPValue != "" {
		if addr, err := netip.ParseAddr(trustedIPValue); err == nil {
			return trustedIPValue, addr
		}
	}

	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 20 {
			ips = ips[len(ips)-20:]
		}
		for i := len(ips) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(ips[i]))
			if err != nil {
				continue
			}
			if !isTrustedProxyAddr(addr, trustedProxies) {
				return strings.TrimSpace(ips[i]), addr
			}
		}
	}

	if xRealIP != "" {
		if addr, err := netip.ParseAddr(xRealIP); err == nil {
			return xRealIP, addr
		}
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip, netip.Addr{}
	}
	return ip, addr
}

// isTrustedProxy returns true if the IP is in the trusted proxies list.
func isTrustedProxy(ip string, trustedProxies []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return isTrustedProxyAddr(addr, trustedProxies)
}

func isTrustedProxyAddr(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// isExemptIP returns true if the IP falls within any CIDR range in the exempt IPs list.
func (b *Bouncer) isExemptIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range b.ExemptIPs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseError is returned when parsing the CheckRequest fails.
type ParseError struct{ Reason string }

// ParsedRequest holds the fields extracted from the gRPC CheckRequest for remediation logic.
type ParsedRequest struct {
	IP           string
	RealIP       string
	ParsedRealIP netip.Addr
	Headers      map[string]string
	Cookies      map[string]string
	URL          url.URL
	Method       string
	UserAgent    string
	Body         []byte
	ProtoMajor   int
	ProtoMinor   int
}

func (e *ParseError) Error() string { return e.Reason }

type CheckedRequest struct {
	IP             string
	Action         string
	Reason         string
	HTTPStatus     int
	RedirectURL    string
	Decision       *models.Decision
	ParsedRequest  *ParsedRequest
	CaptchaSession *components.CaptchaSession
}

func NewCheckedRequest(ip, action, reason string, httpStatus int, decision *models.Decision, redirectURL string, parsedRequest *ParsedRequest, session *components.CaptchaSession) CheckedRequest {
	return CheckedRequest{
		IP:             ip,
		Action:         action,
		Reason:         reason,
		HTTPStatus:     httpStatus,
		Decision:       decision,
		RedirectURL:    redirectURL,
		ParsedRequest:  parsedRequest,
		CaptchaSession: session,
	}
}

func parseIPNets(addresses []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, addr := range addresses {
		if !strings.Contains(addr, "/") {
			suffix := "/32"
			if strings.Contains(addr, ":") {
				suffix = "/128"
			}
			addr = addr + suffix
		}

		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %v", addr, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

// Check runs bouncer first, then captcha if enabled, then WAF if enabled, and returns the result.
func (b *Bouncer) Check(ctx context.Context, req *auth.CheckRequest) CheckedRequest {

	parsed := b.ParseCheckRequest(ctx, req)
	log := logger.FromContext(ctx)

	if b.isExemptIP(parsed.ParsedRealIP) {
		log.Debug("ip is in exempt list, skipping request check", slog.String("ip", parsed.RealIP))
		result := NewCheckedRequest(parsed.RealIP, "allow", "ip is in exempt list", http.StatusOK, nil, "", parsed, nil)
		b.recordFinalMetric(result)
		return result
	}

	bouncerResult := b.checkDecisionCache(ctx, parsed)

	switch bouncerResult.Action {
	case "allow":
	case "captcha":
		captchaResult := b.checkCaptcha(ctx, parsed, bouncerResult.Decision)
		b.recordFinalMetric(captchaResult)
		return captchaResult
	case "ban":
		if bouncerResult.HTTPStatus == 0 {
			bouncerResult.HTTPStatus = b.getBanStatusCode()
		}
		b.recordFinalMetric(bouncerResult)
		return bouncerResult
	case "error":
		finalResult := NewCheckedRequest(parsed.RealIP, "error", bouncerResult.Reason, http.StatusInternalServerError, nil, "", parsed, nil)
		b.recordFinalMetric(finalResult)
		return finalResult
	default:
		finalResult := NewCheckedRequest(parsed.RealIP, "ban", "unknown decision cache action", b.getBanStatusCode(), nil, "", parsed, nil)
		b.recordFinalMetric(finalResult)
		return finalResult
	}

	wafResult := b.checkWAF(ctx, parsed)

	switch wafResult.Action {
	case "allow":
		finalResult := NewCheckedRequest(parsed.RealIP, "allow", "ok", http.StatusOK, bouncerResult.Decision, "", parsed, nil)
		b.recordFinalMetric(finalResult)
		return finalResult
	case "captcha":
		captchaResult := b.checkCaptcha(ctx, parsed, bouncerResult.Decision)
		b.recordFinalMetric(captchaResult)
		return captchaResult
	case "ban":
		b.recordFinalMetric(wafResult)
		return wafResult
	case "error":
		b.recordFinalMetric(wafResult)
		return wafResult
	default:
		finalResult := NewCheckedRequest(parsed.RealIP, wafResult.Action, "unknown action", http.StatusInternalServerError, nil, "", parsed, nil)
		b.recordFinalMetric(finalResult)
		return finalResult
	}
}

func (b *Bouncer) checkDecisionCache(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.DecisionCache == nil {
		return NewCheckedRequest(parsed.RealIP, "allow", "decision cache disabled", http.StatusOK, nil, "", parsed, nil)
	}
	stop := b.PrometheusRecorder.ObserveComponentDuration("decision_cache")
	defer stop()

	logger.Debug("running decision cache", slog.String("ip", parsed.RealIP))
	decision, err := b.DecisionCache.GetDecision(ctx, parsed.RealIP)
	if err != nil {
		logger.Error("decision cache error", "error", err, slog.String("ip", parsed.RealIP))
		return NewCheckedRequest(parsed.RealIP, "error", "decision cache error", http.StatusInternalServerError, nil, "", parsed, nil)
	}

	if decision == nil {
		logger.Debug("no decision found", slog.String("ip", parsed.RealIP))
		return NewCheckedRequest(parsed.RealIP, "allow", "no decision", http.StatusOK, nil, "", parsed, nil)
	}

	if decision.Type == nil {
		logger.Debug("decision has no type", slog.String("ip", parsed.RealIP))
		return NewCheckedRequest(parsed.RealIP, "allow", "no decision type", http.StatusOK, nil, "", parsed, nil)
	}

	decisionType := strings.ToLower(*decision.Type)
	logger.Debug("decision found", "type", decisionType, slog.String("ip", parsed.RealIP))

	switch decisionType {
	case "ban":
		reason := "crowdsec ban"
		if decision.Scenario != nil && *decision.Scenario != "" {
			reason = *decision.Scenario
		}
		return NewCheckedRequest(parsed.RealIP, "ban", reason, b.getBanStatusCode(), decision, "", parsed, nil)
	case "captcha":
		return NewCheckedRequest(parsed.RealIP, "captcha", "crowdsec captcha", http.StatusFound, decision, "", parsed, nil)
	default:
		return NewCheckedRequest(parsed.RealIP, "allow", "decision allows", http.StatusOK, nil, "", parsed, nil)
	}
}

func (b *Bouncer) getBanStatusCode() int {
	if b.config.Bouncer.BanStatusCode != 0 {
		return b.config.Bouncer.BanStatusCode
	}
	return http.StatusForbidden
}

func (b *Bouncer) checkCaptcha(ctx context.Context, parsed *ParsedRequest, decision *models.Decision) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.CaptchaService == nil || !b.CaptchaService.IsEnabled() {
		return NewCheckedRequest(parsed.RealIP, "allow", "captcha disabled", http.StatusOK, nil, "", parsed, nil)
	}
	stop := b.PrometheusRecorder.ObserveComponentDuration("captcha")
	defer stop()

	logger.Debug("running captcha", slog.String("ip", parsed.RealIP))
	originalURL := parsed.URL.String()

	sessionToken := parsed.Cookies[b.CaptchaService.CookieName()]

	session, err := b.CaptchaService.CreateSession(parsed.RealIP, originalURL, sessionToken)
	if err != nil {
		logger.Error("error creating session", "error", err, slog.String("ip", parsed.RealIP))
		b.PrometheusRecorder.IncCaptchaErrorsTotal()
		return NewCheckedRequest(parsed.RealIP, "error", "captcha error", http.StatusInternalServerError, nil, "", parsed, nil)
	}
	if session == nil {
		return NewCheckedRequest(parsed.RealIP, "allow", "captcha not required", http.StatusOK, nil, "", parsed, nil)
	}
	return NewCheckedRequest(parsed.RealIP, "captcha", "captcha required", http.StatusFound, decision, session.ChallengeURL, parsed, session)
}

func (b *Bouncer) checkWAF(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.WAF == nil {
		return NewCheckedRequest(parsed.RealIP, "allow", "waf disabled", http.StatusOK, nil, "", parsed, nil)
	}
	stop := b.PrometheusRecorder.ObserveComponentDuration("waf")
	defer stop()

	logger.Debug("running WAF", slog.String("ip", parsed.RealIP))

	wafReq := components.AppSecRequest{
		Method:     parsed.Method,
		URL:        parsed.URL,
		Headers:    parsed.Headers,
		Body:       parsed.Body,
		RealIP:     parsed.RealIP,
		ProtoMajor: parsed.ProtoMajor,
		ProtoMinor: parsed.ProtoMinor,
	}

	wafResult, wafErr := b.WAF.Inspect(ctx, wafReq)
	if wafErr != nil {
		logger.Debug("waf error", "error", wafErr, slog.String("ip", parsed.RealIP))
		b.PrometheusRecorder.IncWAFErrorsTotal()
		if b.config.WAF.FailOpen {
			return NewCheckedRequest(parsed.RealIP, "allow", "", http.StatusOK, nil, "", parsed, nil)
		}
		return NewCheckedRequest(parsed.RealIP, "error", "error", http.StatusInternalServerError, nil, "", parsed, nil)
	}

	b.PrometheusRecorder.IncWAFRequestsTotal(wafResult.Action)

	if wafResult.Action != "allow" {
		return NewCheckedRequest(parsed.RealIP, wafResult.Action, "ban", b.getBanStatusCode(), nil, "", parsed, nil)
	}

	return NewCheckedRequest(parsed.RealIP, wafResult.Action, "ok", http.StatusOK, nil, "", parsed, nil)
}

// ParseCheckRequest extracts relevant fields from the gRPC CheckRequest for remediation.
func (b *Bouncer) ParseCheckRequest(ctx context.Context, req *auth.CheckRequest) *ParsedRequest {
	parsedRequest := &ParsedRequest{}
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

	var xForwardedFor, xRealIP, trustedValue, cookieHeader string
	for k, v := range httpRequest.Headers {
		lower := strings.ToLower(k)
		if b.TrustedIPHeader != "" && strings.EqualFold(k, b.TrustedIPHeader) {
			trustedValue = v
		}
		switch lower {
		case ":scheme":
			parsedRequest.URL.Scheme = v
		case ":authority":
			parsedRequest.URL.Host = v
		case ":path":
			parsedRequest.URL.Path = v
		case ":method":
			parsedRequest.Method = v
		case "user-agent":
			parsedRequest.UserAgent = v
		case "cookie":
			cookieHeader = v
		case "x-forwarded-for":
			xForwardedFor = v
		case "x-real-ip":
			xRealIP = v
		}
		if b.WAF != nil {
			if parsedRequest.Headers == nil {
				parsedRequest.Headers = make(map[string]string, len(httpRequest.Headers))
			}
			parsedRequest.Headers[lower] = v
		}
	}

	if b.CaptchaService != nil && cookieHeader != "" {
		parsedRequest.Cookies = parseCookies(cookieHeader)
	}

	parsedRequest.RealIP, parsedRequest.ParsedRealIP = ExtractRealIP(parsedRequest.IP, xForwardedFor, xRealIP, trustedValue, b.TrustedProxies)

	if b.WAF != nil && len(httpRequest.GetBody()) > 0 {
		parsedRequest.Body = []byte(httpRequest.GetBody())
	}

	if proto := httpRequest.GetProtocol(); proto != "" {
		maj, min := parseHTTPVersion(proto)
		parsedRequest.ProtoMajor = maj
		parsedRequest.ProtoMinor = min
	}

	return parsedRequest
}

func parseCookies(cookieHeader string) map[string]string {
	if cookieHeader == "" {
		return nil
	}

	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return nil
	}

	m := make(map[string]string, len(cookies))
	for _, c := range cookies {
		m[c.Name] = c.Value
	}

	return m
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
