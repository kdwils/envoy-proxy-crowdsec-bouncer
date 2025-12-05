package bouncer

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

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec"
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
	RequiresCaptcha(ip, verificationToken string) bool
	CreateSession(ip, originalURL, verificationToken string) (*components.CaptchaSession, error)
	GetSession(sessionID string) (*components.CaptchaSession, bool)
	VerifyResponse(ctx context.Context, sessionID string, req components.VerificationRequest) (*components.VerificationResult, error)
}

func ptr[T any](v T) *T {
	return &v
}

type Bouncer struct {
	DecisionCache  DecisionCache
	WAF            WAF
	CaptchaService CaptchaService
	TrustedProxies []*net.IPNet
	MetricsService *crowdsec.MetricsService
	config         config.Config
}

func New(cfg config.Config) (*Bouncer, error) {
	trustedProxies, err := parseProxyAddresses(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}

	bouncer := &Bouncer{
		TrustedProxies: trustedProxies,
		config:         cfg,
	}

	if cfg.Bouncer.Enabled && cfg.Bouncer.Metrics {
		userAgent := "envoy-proxy-crowdsec-bouncer/" + version.Version
		client, err := crowdsec.NewClient(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, userAgent)
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
		dc, err = components.NewDecisionCache(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, cfg.Bouncer.TickerInterval, bouncer.MetricsService)
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

	bouncer.DecisionCache = dc
	bouncer.WAF = w
	bouncer.CaptchaService = c

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

func (b *Bouncer) incRemediationMetric(name, remediationType string) {
	if b.MetricsService == nil {
		return
	}
	origin := "CAPI"
	key := origin + ":" + remediationType
	b.MetricsService.Inc(key, name, "request", map[string]string{
		"origin":      origin,
		"remediation": remediationType,
	})
}

func (b *Bouncer) recordFinalMetric(result CheckedRequest) {
	switch result.Action {
	case "allow":
		b.incRemediationMetric("processed", "bypass")
	case "deny":
		b.incRemediationMetric("dropped", "ban")
	case "captcha":
		b.incRemediationMetric("dropped", "captcha")
	default:
		b.incRemediationMetric("dropped", "ban")
	}
}

// ExtractRealIPFromHTTP extracts the real client IP from an HTTP request using trusted proxy logic.
func (b *Bouncer) ExtractRealIPFromHTTP(r *http.Request) string {
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ExtractRealIP(host, headers, b.TrustedProxies)
}

// ExtractRealIP determines the real client IP from headers and socket address, matching bouncer logic.
// Headers are checked case-insensitively to handle both normalized and original casing.
func ExtractRealIP(ip string, headers map[string]string, trustedProxies []*net.IPNet) string {
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
	Cookies    map[string]string
	URL        url.URL
	Method     string
	UserAgent  string
	Body       []byte
	ProtoMajor int
	ProtoMinor int
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
func (b *Bouncer) Check(ctx context.Context, req *auth.CheckRequest) CheckedRequest {

	parsed := b.ParseCheckRequest(ctx, req)
	ctx = logger.WithContext(ctx, logger.FromContext(ctx).With(slog.String("ip", parsed.RealIP)))

	bouncerResult := b.checkDecisionCache(ctx, parsed)
	switch bouncerResult.Action {
	case "allow":
	case "captcha":
		captchaResult := b.checkCaptcha(ctx, parsed, bouncerResult.Decision)
		b.recordFinalMetric(captchaResult)
		return captchaResult
	case "deny", "ban":
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
		finalResult := NewCheckedRequest(parsed.RealIP, "deny", "unknown decision cache action", b.getBanStatusCode(), nil, "", parsed, nil)
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
	case "deny", "ban":
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

	logger.Debug("running decision cache")
	decision, err := b.DecisionCache.GetDecision(ctx, parsed.RealIP)
	if err != nil {
		logger.Error("decision cache error", "error", err)
		return NewCheckedRequest(parsed.RealIP, "error", "decision cache error", http.StatusInternalServerError, nil, "", parsed, nil)
	}

	if decision == nil {
		logger.Debug("no decision found")
		return NewCheckedRequest(parsed.RealIP, "allow", "no decision", http.StatusOK, nil, "", parsed, nil)
	}

	if decision.Type == nil {
		logger.Debug("decision has no type")
		return NewCheckedRequest(parsed.RealIP, "allow", "no decision type", http.StatusOK, nil, "", parsed, nil)
	}

	decisionType := strings.ToLower(*decision.Type)
	logger.Debug("decision found", "type", decisionType)

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

	logger.Debug("running captcha")
	originalURL := parsed.URL.String()

	verificationToken := parsed.Cookies["captcha_verified"]

	session, err := b.CaptchaService.CreateSession(parsed.RealIP, originalURL, verificationToken)
	if err != nil {
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

	wafResult, wafErr := b.WAF.Inspect(ctx, wafReq)
	if wafErr != nil {
		logger.Error("waf error", "error", wafErr)
		return NewCheckedRequest(parsed.RealIP, "error", "error", http.StatusInternalServerError, nil, "", parsed, nil)
	}

	if wafResult.Action != "allow" {
		return NewCheckedRequest(parsed.RealIP, wafResult.Action, "ban", b.getBanStatusCode(), nil, "", parsed, nil)
	}

	return NewCheckedRequest(parsed.RealIP, wafResult.Action, "ok", http.StatusOK, nil, "", parsed, nil)
}

// ParseCheckRequest extracts relevant fields from the gRPC CheckRequest for remediation.
func (b *Bouncer) ParseCheckRequest(ctx context.Context, req *auth.CheckRequest) *ParsedRequest {
	parsedRequest := &ParsedRequest{
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
	}
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

	parsedRequest.Cookies = parseCookies(parsedRequest.Headers["cookie"])

	parsedRequest.RealIP = ExtractRealIP(parsedRequest.IP, parsedRequest.Headers, b.TrustedProxies)

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

func parseCookies(cookieHeader string) map[string]string {
	m := make(map[string]string)
	if cookieHeader == "" {
		return m
	}

	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return m
	}

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
