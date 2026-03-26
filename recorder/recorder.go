package recorder

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "bouncer"

type Metrics struct {
	RequestsTotal             *prometheus.CounterVec
	RequestDuration           *prometheus.HistogramVec
	DecisionCacheSize         *prometheus.GaugeVec
	DecisionCacheMatchesTotal *prometheus.CounterVec
	WAFRequestsTotal          *prometheus.CounterVec
	CaptchaChallengesTotal    prometheus.Counter
	CaptchaVerificationsTotal *prometheus.CounterVec
	RateLimitedTotal          prometheus.Counter
	LAPIStreamConnected       prometheus.Gauge
	LAPILastSyncTimestamp     prometheus.Gauge
	ExternalCallErrorsTotal   *prometheus.CounterVec
}

type Recorder struct {
	m   *Metrics
	now func() time.Time
}

func (r *Recorder) GetMetrics() *Metrics {
	return r.m
}

func newMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Total number of requests processed by action outcome.",
		}, []string{"action"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "Duration of request processing by component.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"component"}),
		DecisionCacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "decision_cache_size",
			Help:      "Number of decisions in the cache by origin.",
		}, []string{"origin"}),
		DecisionCacheMatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "decision_cache_matches_total",
			Help:      "Total number of IPs that matched an active decision in the cache by decision type.",
		}, []string{"type"}),
		WAFRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "waf_requests_total",
			Help:      "Total number of WAF inspection requests by action.",
		}, []string{"action"}),
		CaptchaChallengesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "captcha_challenges_total",
			Help:      "Total number of CAPTCHA challenges served.",
		}),
		CaptchaVerificationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "captcha_verifications_total",
			Help:      "Total number of CAPTCHA verifications by result.",
		}, []string{"result"}),
		RateLimitedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limited_total",
			Help:      "Total number of rate limited requests.",
		}),
		LAPIStreamConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "lapi_stream_connected",
			Help:      "Whether the LAPI decision stream is connected (1) or not (0).",
		}),
		LAPILastSyncTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "lapi_last_sync_timestamp_seconds",
			Help:      "Unix timestamp of the last successful LAPI decision sync.",
		}),
		ExternalCallErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "external_call_errors_total",
			Help:      "Total number of errors from external service calls.",
		}, []string{"service"}),
	}

	collectors := []prometheus.Collector{
		m.RequestsTotal,
		m.RequestDuration,
		m.DecisionCacheSize,
		m.DecisionCacheMatchesTotal,
		m.WAFRequestsTotal,
		m.CaptchaChallengesTotal,
		m.CaptchaVerificationsTotal,
		m.RateLimitedTotal,
		m.LAPIStreamConnected,
		m.LAPILastSyncTimestamp,
		m.ExternalCallErrorsTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func New(reg prometheus.Registerer) (*Recorder, error) {
	if reg == nil {
		return &Recorder{now: time.Now}, nil
	}

	m, err := newMetrics(reg)
	if err != nil {
		return nil, err
	}

	return &Recorder{m: m, now: time.Now}, nil
}

func (r *Recorder) ObserveDuration(component string) func() {
	if r.m == nil {
		return func() {}
	}
	start := r.now()
	return func() {
		r.m.RequestDuration.WithLabelValues(component).Observe(r.now().Sub(start).Seconds())
	}
}

func (r *Recorder) IncRequestsTotal(action string) {
	if r.m == nil {
		return
	}
	r.m.RequestsTotal.WithLabelValues(action).Inc()
}

func (r *Recorder) IncDecisionCacheMatchesTotal(decisionType string) {
	if r.m == nil {
		return
	}
	r.m.DecisionCacheMatchesTotal.WithLabelValues(decisionType).Inc()
}

func (r *Recorder) SetDecisionCacheSize(origin string, val float64) {
	if r.m == nil {
		return
	}
	r.m.DecisionCacheSize.WithLabelValues(origin).Set(val)
}

func (r *Recorder) IncWAFRequestsTotal(action string) {
	if r.m == nil {
		return
	}
	r.m.WAFRequestsTotal.WithLabelValues(action).Inc()
}

func (r *Recorder) IncCaptchaChallengesTotal() {
	if r.m == nil {
		return
	}
	r.m.CaptchaChallengesTotal.Inc()
}

func (r *Recorder) IncCaptchaVerificationsTotal(result string) {
	if r.m == nil {
		return
	}
	r.m.CaptchaVerificationsTotal.WithLabelValues(result).Inc()
}

func (r *Recorder) IncRateLimitedTotal() {
	if r.m == nil {
		return
	}
	r.m.RateLimitedTotal.Inc()
}

func (r *Recorder) IncExternalCallErrorsTotal(service string) {
	if r.m == nil {
		return
	}
	r.m.ExternalCallErrorsTotal.WithLabelValues(service).Inc()
}

func (r *Recorder) SetLAPIStreamConnected(connected bool) {
	if r.m == nil {
		return
	}
	v := float64(0)
	if connected {
		v = 1
	}
	r.m.LAPIStreamConnected.Set(v)
}

func (r *Recorder) SetLAPILastSyncTimestamp() {
	if r.m == nil {
		return
	}
	r.m.LAPILastSyncTimestamp.Set(float64(r.now().Unix()))
}
