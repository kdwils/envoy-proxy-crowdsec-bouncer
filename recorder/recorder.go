package recorder

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "bouncer"

type Metrics struct {
	RequestsTotal                 *prometheus.CounterVec
	RequestDuration               prometheus.Histogram
	DecisionCacheSize             *prometheus.GaugeVec
	CaptchaChallengesTotal        prometheus.Counter
	CaptchaVerificationsTotal     *prometheus.CounterVec
	RateLimitedTotal              prometheus.Counter
	LAPIStreamConnected           prometheus.Gauge
	LAPILastSyncTimestamp         prometheus.Gauge
	WAFRequestsTotal              *prometheus.CounterVec
	WAFErrorsTotal                prometheus.Counter
	ComponentDuration             *prometheus.HistogramVec
	LAPIDecisionsAddedTotal       *prometheus.CounterVec
	LAPIDecisionsDeletedTotal     *prometheus.CounterVec
	CaptchaPendingChallenges      prometheus.Gauge
	CaptchaExpiredChallengesTotal prometheus.Counter
	CaptchaErrorsTotal            prometheus.Counter
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
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "Duration of request processing.",
			Buckets:   prometheus.DefBuckets,
		}),
		DecisionCacheSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "decision_cache_size",
			Help:      "Number of decisions in the cache by origin.",
		}, []string{"origin"}),
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
		WAFRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "waf_requests_total",
			Help:      "Total number of requests inspected by the WAF by action outcome.",
		}, []string{"action"}),
		WAFErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "waf_errors_total",
			Help:      "Total number of WAF inspection errors.",
		}),
		ComponentDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "component_duration_seconds",
			Help:      "Duration of individual component processing.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"component"}),
		LAPIDecisionsAddedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "lapi_decisions_added_total",
			Help:      "Total number of decisions added to the cache by origin.",
		}, []string{"origin"}),
		LAPIDecisionsDeletedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "lapi_decisions_deleted_total",
			Help:      "Total number of decisions deleted from the cache by origin.",
		}, []string{"origin"}),
		CaptchaPendingChallenges: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "captcha_pending_challenges",
			Help:      "Number of issued CAPTCHA challenge JWTs awaiting verification.",
		}),
		CaptchaExpiredChallengesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "captcha_expired_challenges_total",
			Help:      "Total number of CAPTCHA challenge JWTs that expired without verification.",
		}),
		CaptchaErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "captcha_errors_total",
			Help:      "Total number of captcha service errors.",
		}),
	}

	collectors := []prometheus.Collector{
		m.RequestsTotal,
		m.RequestDuration,
		m.DecisionCacheSize,
		m.CaptchaChallengesTotal,
		m.CaptchaVerificationsTotal,
		m.RateLimitedTotal,
		m.LAPIStreamConnected,
		m.LAPILastSyncTimestamp,
		m.WAFRequestsTotal,
		m.WAFErrorsTotal,
		m.ComponentDuration,
		m.LAPIDecisionsAddedTotal,
		m.LAPIDecisionsDeletedTotal,
		m.CaptchaPendingChallenges,
		m.CaptchaExpiredChallengesTotal,
		m.CaptchaErrorsTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func NewNoOp() *Recorder {
	return &Recorder{now: time.Now}
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

func (r *Recorder) ObserveDuration() func() {
	if r.m == nil {
		return func() {}
	}
	start := r.now()
	return func() {
		r.m.RequestDuration.Observe(r.now().Sub(start).Seconds())
	}
}

func (r *Recorder) IncRequestsTotal(action string) {
	if r.m == nil {
		return
	}
	r.m.RequestsTotal.WithLabelValues(action).Inc()
}

func (r *Recorder) SetDecisionCacheSize(origin string, val float64) {
	if r.m == nil {
		return
	}
	r.m.DecisionCacheSize.WithLabelValues(origin).Set(val)
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

func (r *Recorder) IncWAFRequestsTotal(action string) {
	if r.m == nil {
		return
	}
	r.m.WAFRequestsTotal.WithLabelValues(action).Inc()
}

func (r *Recorder) IncWAFErrorsTotal() {
	if r.m == nil {
		return
	}
	r.m.WAFErrorsTotal.Inc()
}

func (r *Recorder) ObserveComponentDuration(component string) func() {
	if r.m == nil {
		return func() {}
	}
	start := r.now()
	return func() {
		r.m.ComponentDuration.WithLabelValues(component).Observe(r.now().Sub(start).Seconds())
	}
}

func (r *Recorder) IncLAPIDecisionsAddedTotal(origin string) {
	if r.m == nil {
		return
	}
	r.m.LAPIDecisionsAddedTotal.WithLabelValues(origin).Inc()
}

func (r *Recorder) IncLAPIDecisionsDeletedTotal(origin string) {
	if r.m == nil {
		return
	}
	r.m.LAPIDecisionsDeletedTotal.WithLabelValues(origin).Inc()
}

func (r *Recorder) IncCaptchaPendingChallenges() {
	if r.m == nil {
		return
	}
	r.m.CaptchaPendingChallenges.Inc()
}

func (r *Recorder) DecCaptchaPendingChallenges() {
	if r.m == nil {
		return
	}
	r.m.CaptchaPendingChallenges.Dec()
}

func (r *Recorder) IncCaptchaExpiredChallengesTotal() {
	if r.m == nil {
		return
	}
	r.m.CaptchaExpiredChallengesTotal.Inc()
}

func (r *Recorder) IncCaptchaErrorsTotal() {
	if r.m == nil {
		return
	}
	r.m.CaptchaErrorsTotal.Inc()
}
