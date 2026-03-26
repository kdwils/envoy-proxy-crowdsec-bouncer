package recorder

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecorder_NilReg_NoOp(t *testing.T) {
	r, err := New(nil)
	require.NoError(t, err)
	r.IncRequestsTotal("allow")
	r.SetDecisionCacheSize("capi", 0)
	r.IncCaptchaChallengesTotal()
	r.IncCaptchaVerificationsTotal("success")
	r.IncRateLimitedTotal()
	r.SetLAPIStreamConnected(true)
	r.SetLAPILastSyncTimestamp()
	done := r.ObserveDuration()
	done()
}

func TestRecorder_IncRequestsTotal(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.IncRequestsTotal("allow")
	r.IncRequestsTotal("allow")
	r.IncRequestsTotal("ban")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.RequestsTotal.WithLabelValues("allow")), "expected 2 allow requests")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RequestsTotal.WithLabelValues("ban")), "expected 1 ban request")
}

func TestRecorder_SetDecisionCacheSize(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.SetDecisionCacheSize("capi", 42)
	assert.Equal(t, float64(42), testutil.ToFloat64(m.DecisionCacheSize.WithLabelValues("capi")), "expected cache size of 42")

	r.SetDecisionCacheSize("capi", 10)
	assert.Equal(t, float64(10), testutil.ToFloat64(m.DecisionCacheSize.WithLabelValues("capi")), "expected cache size of 10 after update")
}

func TestRecorder_IncCaptchaChallengesTotal(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.IncCaptchaChallengesTotal()
	r.IncCaptchaChallengesTotal()

	assert.Equal(t, float64(2), testutil.ToFloat64(m.CaptchaChallengesTotal), "expected 2 captcha challenges")
}

func TestRecorder_IncCaptchaVerificationsTotal(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.IncCaptchaVerificationsTotal("success")
	r.IncCaptchaVerificationsTotal("error")
	r.IncCaptchaVerificationsTotal("success")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.CaptchaVerificationsTotal.WithLabelValues("success")), "expected 2 successful verifications")
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CaptchaVerificationsTotal.WithLabelValues("error")), "expected 1 verification error")
}

func TestRecorder_IncRateLimitedTotal(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.IncRateLimitedTotal()
	r.IncRateLimitedTotal()
	r.IncRateLimitedTotal()

	assert.Equal(t, float64(3), testutil.ToFloat64(m.RateLimitedTotal), "expected 3 rate limited requests")
}

func TestRecorder_SetLAPIStreamConnected(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }}

	r.SetLAPIStreamConnected(true)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.LAPIStreamConnected), "expected stream connected")

	r.SetLAPIStreamConnected(false)
	assert.Equal(t, float64(0), testutil.ToFloat64(m.LAPIStreamConnected), "expected stream disconnected")
}

func TestRecorder_SetLAPILastSyncTimestamp(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)

	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Recorder{m: m, now: func() time.Time { return fixed }}

	r.SetLAPILastSyncTimestamp()

	assert.Equal(t, float64(fixed.Unix()), testutil.ToFloat64(m.LAPILastSyncTimestamp), "expected timestamp to match fixed time")
}

func TestDecisionCacheGauge_SetZeroRetainsLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)
	r := &Recorder{m: m, now: time.Now}

	r.SetDecisionCacheSize("capi", 5)
	r.SetDecisionCacheSize("capi", 0)

	count := testutil.CollectAndCount(m.DecisionCacheSize)
	assert.Equal(t, 1, count, "expected label to persist in scrape after Set(0) — only DeleteLabelValues removes a label")
	assert.Equal(t, float64(0), testutil.ToFloat64(m.DecisionCacheSize.WithLabelValues("capi")), "expected value 0")
}

func TestRecorder_ObserveDuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg)
	require.NoError(t, err)

	tick := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Recorder{m: m, now: func() time.Time {
		t := tick
		tick = tick.Add(time.Second)
		return t
	}}

	done := r.ObserveDuration()
	done()

	assert.Equal(t, 1, testutil.CollectAndCount(m.RequestDuration), "expected 1 observation")
}
