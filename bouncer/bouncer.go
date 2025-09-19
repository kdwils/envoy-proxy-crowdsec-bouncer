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
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/crowdsec"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	bouncerVersion "github.com/kdwils/envoy-proxy-bouncer/version"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type Metrics struct {
	Remediation map[string]RemediationMetrics `json:"remediation"`
}

type RemediationMetrics struct {
	Name            string `json:"name"`
	Origin          string `json:"origin"`
	RemediationType string `json:"remediation_type"`
	Count           int64  `json:"count"`
}

type MetricLabels struct {
	Name            string
	RemediationType string
}

//go:generate mockgen -destination=mocks/mock_waf.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer WAF
type WAF interface {
	Inspect(ctx context.Context, req components.AppSecRequest) (components.WAFResponse, error)
}

//go:generate mockgen -destination=mocks/mock_decision_cache.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer DecisionCache
type DecisionCache interface {
	GetDecision(ctx context.Context, ip string) (*models.Decision, error)
	Sync(ctx context.Context) error
}

//go:generate mockgen -destination=mocks/mock_captcha_service.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/bouncer CaptchaService
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

type MetricsProvider interface {
	SendMetrics(ctx context.Context, metrics *models.AllMetrics) error
}

func ptr[T any](v T) *T {
	return &v
}

type Bouncer struct {
	DecisionCache   DecisionCache
	WAF             WAF
	CaptchaService  CaptchaService
	TrustedProxies  []*net.IPNet
	metrics         *cache.Cache[RemediationMetrics]
	metricsProvider MetricsProvider
	config          config.Config
}

// New creates a Bouncer from config.Config, instantiating decision cache and WAF only if enabled.
func New(cfg config.Config) (*Bouncer, error) {
	trustedProxies, err := parseProxyAddresses(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	var dc DecisionCache
	if cfg.Bouncer.Enabled {
		dc, err = components.NewDecisionCache(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, cfg.Bouncer.TickerInterval, cfg.Bouncer.CacheCleanupInterval)
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

	metricsCleanupInterval := cfg.Bouncer.CacheCleanupInterval
	if metricsCleanupInterval == 0 {
		metricsCleanupInterval = 5 * time.Minute
	}

	bouncer := &Bouncer{
		DecisionCache:  dc,
		WAF:            w,
		CaptchaService: c,
		TrustedProxies: trustedProxies,
		config:         cfg,
		metrics:        cache.New(cache.WithCleanupInterval[RemediationMetrics](metricsCleanupInterval)),
	}

	if cfg.Bouncer.Enabled && cfg.Bouncer.Metrics {
		userAgent := "envoy-proxy-crowdsec-bouncer/" + version.Version
		client, err := crowdsec.NewClient(cfg.Bouncer.ApiKey, cfg.Bouncer.LAPIURL, userAgent)
		if err != nil {
			return nil, err
		}

		provider, err := components.NewMetricsProvider(client)
		if err != nil {
			return nil, err
		}

		bouncer.metricsProvider = provider
	}

	return bouncer, nil
}

func (bouncer *Bouncer) CalculateMetrics(interval time.Duration) *models.AllMetrics {
	currentMetrics := bouncer.GetMetrics()

	var items []*models.MetricsDetailItem

	for _, remediation := range currentMetrics.Remediation {
		items = append(items, &models.MetricsDetailItem{
			Name:  ptr(remediation.Name),
			Unit:  ptr(remediation.RemediationType),
			Value: ptr(float64(remediation.Count)),
			Labels: map[string]string{
				"origin":      remediation.Origin,
				"remediation": remediation.RemediationType,
			},
		})
	}

	windowSizeSeconds := int64(interval.Seconds())
	utcNowTimestamp := time.Now().Unix()

	detailedMetrics := []*models.DetailedMetrics{
		{
			Items: items,
			Meta: &models.MetricsMeta{
				UtcNowTimestamp:   &utcNowTimestamp,
				WindowSizeSeconds: &windowSizeSeconds,
			},
		},
	}

	startupTS := time.Now().Unix()

	osName, osVersion := version.DetectOS()

	version := bouncerVersion.Version

	baseMetrics := &models.BaseMetrics{
		Os: &models.OSversion{
			Name:    &osName,
			Version: &osVersion,
		},
		Version:             &version,
		FeatureFlags:        []string{},
		Metrics:             detailedMetrics,
		UtcStartupTimestamp: &startupTS,
	}

	remediationMetrics := &models.RemediationComponentsMetrics{
		BaseMetrics: *baseMetrics,
		Type:        "envoy-proxy-crowdsec-bouncer",
	}

	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{remediationMetrics},
	}
}

func (b *Bouncer) Sync(ctx context.Context) error {
	if b.DecisionCache == nil {
		return errors.New("decision cache not initialized")
	}
	return b.DecisionCache.Sync(ctx)
}

func (b *Bouncer) Metrics(ctx context.Context) error {
	log := logger.FromContext(ctx)
	if b.metricsProvider == nil {
		return nil
	}

	interval := b.config.Bouncer.MetricsInterval

	if interval == 0 {
		return nil
	}

	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			allMetrics := b.CalculateMetrics(interval)
			log.Debug("sending metrics update", slog.Any("metrics", allMetrics))
			err := b.metricsProvider.SendMetrics(ctx, allMetrics)
			if err == nil {
				b.ResetMetrics()
			}
		}
	}
}

func (b *Bouncer) SendMetrics(ctx context.Context, metrics *models.AllMetrics) error {
	if b.metricsProvider == nil {
		return errors.New("metrics provider not available")
	}
	err := b.metricsProvider.SendMetrics(ctx, metrics)
	if err == nil {
		b.ResetMetrics()
	}
	return err
}

func (b *Bouncer) GetMetrics() Metrics {
	if b.metrics == nil {
		return Metrics{Remediation: make(map[string]RemediationMetrics)}
	}

	metrics := Metrics{
		Remediation: make(map[string]RemediationMetrics),
	}

	for _, key := range b.metrics.Keys() {
		metric, exists := b.metrics.Get(key)
		if exists {
			metrics.Remediation[key] = metric
		}
	}

	return metrics
}

// IncRemediationMetric increments a remediation metric with envoy-proxy-bouncer origin
func (b *Bouncer) IncRemediationMetric(labels MetricLabels) {
	origin := "envoy-proxy-bouncer"
	key := origin + ":" + labels.RemediationType
	metric, exists := b.metrics.Get(key)
	if !exists {
		metric = RemediationMetrics{
			Name:            labels.Name,
			Origin:          origin,
			RemediationType: labels.RemediationType,
			Count:           0,
		}
	}
	metric.Count++
	b.metrics.Set(key, metric)
}

func (b *Bouncer) ResetMetrics() {
	for _, k := range b.metrics.Keys() {
		b.metrics.Delete(k)
	}
}

// extractRealIP determines the real client IP from headers and socket address, matching bouncer logic.
// Headers are checked case-insensitively to handle both normalized and original casing.
func extractRealIP(ip string, headers map[string]string, trustedProxies []*net.IPNet) string {
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
func (b *Bouncer) Check(ctx context.Context, req *auth.CheckRequest) CheckedRequest {
	b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "processed"})

	parsed := b.ParseCheckRequest(ctx, req)
	ctx = logger.WithContext(ctx, logger.FromContext(ctx).With(slog.String("ip", parsed.RealIP)))

	result := b.checkDecisionCache(ctx, parsed)
	switch result.Action {
	case "allow":
	case "captcha":
		captchaResult := b.checkCaptcha(ctx, parsed)
		switch captchaResult.Action {
		case "allow":
			b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "allowed"})
		case "error":
			b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "errored"})
		}
		return captchaResult
	case "deny":
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "denied"})
		return CheckedRequest{IP: parsed.RealIP, Action: "deny", Reason: result.Reason, HTTPStatus: http.StatusForbidden}
	case "error":
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "errored"})
		return CheckedRequest{IP: parsed.RealIP, Action: "deny", Reason: result.Reason, HTTPStatus: http.StatusForbidden}
	default:
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "denied"})
		return CheckedRequest{IP: parsed.RealIP, Action: "deny", Reason: "unknown decision cache action", HTTPStatus: http.StatusForbidden}
	}

	result = b.checkWAF(ctx, parsed)
	switch result.Action {
	case "allow":
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "allowed"})
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "ok", HTTPStatus: http.StatusOK}
	case "captcha":
		captchaResult := b.checkCaptcha(ctx, parsed)
		switch captchaResult.Action {
		case "allow":
			b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "allowed"})
		case "error":
			b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "errored"})
		}
		return captchaResult
	case "deny", "ban":
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "denied"})
		return result
	case "error":
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "errored"})
		return result
	default:
		b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "errored"})
		return CheckedRequest{IP: parsed.RealIP, Action: result.Action, Reason: "unknown action", HTTPStatus: http.StatusInternalServerError}
	}
}

func (b *Bouncer) checkDecisionCache(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.DecisionCache == nil {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "decision cache disabled", HTTPStatus: http.StatusOK}
	}

	logger.Debug("running decision cache")
	decision, err := b.DecisionCache.GetDecision(ctx, parsed.RealIP)
	if err != nil {
		logger.Error("decision cache error", "error", err)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "decision cache error", HTTPStatus: http.StatusInternalServerError}
	}

	if decision == nil {
		logger.Debug("no decision found")
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "no decision", HTTPStatus: http.StatusOK}
	}

	if decision.Type == nil {
		logger.Debug("decision has no type")
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "no decision type", HTTPStatus: http.StatusOK}
	}

	decisionType := strings.ToLower(*decision.Type)
	logger.Debug("decision found", "type", decisionType)

	switch decisionType {
	case "ban":
		return CheckedRequest{IP: parsed.RealIP, Action: "ban", Reason: "crowdsec ban", HTTPStatus: http.StatusForbidden}
	case "captcha":
		return CheckedRequest{IP: parsed.RealIP, Action: "captcha", Reason: "crowdsec captcha", HTTPStatus: http.StatusFound}
	default:
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "decision allows", HTTPStatus: http.StatusOK}
	}
}

func (b *Bouncer) checkCaptcha(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.CaptchaService == nil || !b.CaptchaService.IsEnabled() {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "captcha disabled", HTTPStatus: http.StatusOK}
	}

	logger.Debug("running captcha")
	originalURL := parsed.URL.String()

	challengeURL, err := b.CaptchaService.GenerateChallengeURL(parsed.RealIP, originalURL)
	if err != nil {
		logger.Error("failed to generate captcha challenge", "error", err)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "captcha error", HTTPStatus: http.StatusInternalServerError}
	}

	if challengeURL == "" {
		return CheckedRequest{IP: parsed.RealIP, Action: "allow", Reason: "captcha not required", HTTPStatus: http.StatusOK}
	}

	b.IncRemediationMetric(MetricLabels{Name: "requests", RemediationType: "captcha"})
	return CheckedRequest{
		IP:          parsed.RealIP,
		Action:      "captcha",
		Reason:      "captcha required",
		HTTPStatus:  http.StatusFound,
		RedirectURL: challengeURL,
	}
}

func (b *Bouncer) checkWAF(ctx context.Context, parsed *ParsedRequest) CheckedRequest {
	logger := logger.FromContext(ctx)
	if b.WAF == nil {
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

	wafResult, wafErr := b.WAF.Inspect(ctx, wafReq)
	if wafErr != nil {
		logger.Error("waf error", "error", wafErr)
		return CheckedRequest{IP: parsed.RealIP, Action: "error", Reason: "error", HTTPStatus: http.StatusInternalServerError}
	}

	if wafResult.Action != "allow" {
		return CheckedRequest{IP: parsed.RealIP, Action: wafResult.Action, Reason: "ban", HTTPStatus: http.StatusForbidden}
	}

	return CheckedRequest{IP: parsed.RealIP, Action: wafResult.Action, Reason: "ok", HTTPStatus: http.StatusOK}
}

// ParseCheckRequest extracts relevant fields from the gRPC CheckRequest for remediation.
func (b *Bouncer) ParseCheckRequest(ctx context.Context, req *auth.CheckRequest) *ParsedRequest {
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

	parsedRequest.RealIP = extractRealIP(parsedRequest.IP, parsedRequest.Headers, b.TrustedProxies)

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
