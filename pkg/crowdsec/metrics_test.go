package crowdsec

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec/mocks"
)

const staticStartupTS = int64(1234567890)

func newTestCollector(t *testing.T) *MetricsService {
	t.Helper()

	collector, err := NewMetricsService(MetricsConfig{
		APIClient:   &apiclient.ApiClient{},
		BouncerType: "envoy-proxy",
		Version:     "v1.0.0",
	})
	require.NoError(t, err)

	return collector
}

func newStaticCollector(t *testing.T) *MetricsService {
	collector, err := NewMetricsService(MetricsConfig{
		APIClient:   &apiclient.ApiClient{},
		BouncerType: "envoy-proxy",
		Version:     "v1.0.0",
	})
	require.NoError(t, err)

	collector.startupTS = staticStartupTS

	return collector
}

func newMockCollector(t *testing.T, client CrowdsecClient) *MetricsService {
	collector, err := NewMetricsService(MetricsConfig{
		APIClient:   &apiclient.ApiClient{},
		BouncerType: "envoy-proxy",
		Version:     "v1.0.0",
	})
	require.NoError(t, err)

	collector.apiClient = client

	return collector
}

func sortItems(items []*models.MetricsDetailItem) {
	sort.Slice(items, func(i, j int) bool {
		return *items[i].Name < *items[j].Name
	})
}

func TestNewMetricsService(t *testing.T) {
	t.Run("creates collector with valid config", func(t *testing.T) {
		collector, err := NewMetricsService(MetricsConfig{
			APIClient:   &apiclient.ApiClient{},
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		})

		require.NoError(t, err)
		require.NotNil(t, collector)
		require.NotNil(t, collector.cache)
		require.NotNil(t, collector.apiClient)
		assert.Equal(t, "envoy-proxy", collector.bouncerType)
		assert.Equal(t, "v1.0.0", collector.version)
	})

	t.Run("returns error on invalid config", func(t *testing.T) {
		tests := []struct {
			name string
			cfg  MetricsConfig
			want string
		}{
			{
				name: "nil api client",
				cfg:  MetricsConfig{BouncerType: "envoy-proxy", Version: "v1.0.0"},
				want: "api client is required",
			},
			{
				name: "empty bouncer type",
				cfg:  MetricsConfig{APIClient: &apiclient.ApiClient{}, Version: "v1.0.0"},
				want: "bouncer type is required",
			},
			{
				name: "empty version",
				cfg:  MetricsConfig{APIClient: &apiclient.ApiClient{}, BouncerType: "envoy-proxy"},
				want: "version is required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				collector, err := NewMetricsService(tt.cfg)

				assert.Nil(t, collector)
				require.Error(t, err)
				assert.Equal(t, tt.want, err.Error())
			})
		}
	})
}

func TestMetricsService_Inc(t *testing.T) {
	t.Run("creates and accumulates metric", func(t *testing.T) {
		collector := newTestCollector(t)
		labels := map[string]string{"origin": "capi"}

		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Inc("test_key", "test_metric", "count", labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "count",
			Value:  2,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("increments different metrics independently", func(t *testing.T) {
		collector := newTestCollector(t)

		collector.Inc("key1", "metric1", "count", map[string]string{"type": "a"})
		collector.Inc("key2", "metric2", "count", map[string]string{"type": "b"})

		got := collector.GetSnapshot()

		want := map[string]Metric{
			"key1": {
				Name:   "metric1",
				Unit:   "count",
				Value:  1,
				Labels: map[string]string{"type": "a"},
			},
			"key2": {
				Name:   "metric2",
				Unit:   "count",
				Value:  1,
				Labels: map[string]string{"type": "b"},
			},
		}
		assert.Equal(t, want, got)
	})
}

func TestMetricsService_Dec(t *testing.T) {
	t.Run("decrements metric count", func(t *testing.T) {
		tests := []struct {
			name     string
			incCalls int
			decCalls int
			want     Metric
		}{
			{
				name:     "decrements existing metric",
				incCalls: 3,
				decCalls: 1,
				want: Metric{
					Name:   "test_metric",
					Unit:   "count",
					Value:  2,
					Labels: map[string]string{"origin": "capi"},
				},
			},
			{
				name:     "decrements new metric to zero",
				incCalls: 0,
				decCalls: 1,
				want: Metric{
					Name:   "test_metric",
					Unit:   "count",
					Value:  0,
					Labels: map[string]string{"origin": "capi"},
				},
			},
			{
				name:     "never goes below zero",
				incCalls: 1,
				decCalls: 3,
				want: Metric{
					Name:   "test_metric",
					Unit:   "count",
					Value:  0,
					Labels: map[string]string{"origin": "capi"},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				collector := newTestCollector(t)
				labels := map[string]string{"origin": "capi"}

				for i := 0; i < tt.incCalls; i++ {
					collector.Inc("test_key", "test_metric", "count", labels)
				}
				for i := 0; i < tt.decCalls; i++ {
					collector.Dec("test_key", "test_metric", "count", labels)
				}

				got, ok := collector.cache.Get("test_key")
				require.True(t, ok)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}
func TestMetricsService_Set(t *testing.T) {
	t.Run("sets metric value", func(t *testing.T) {
		collector := newTestCollector(t)

		collector.Set("test_key", "test_metric", "gauge", 42, map[string]string{"origin": "capi"})

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "gauge",
			Value:  42,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})
}

func TestMetricsService_Reset(t *testing.T) {
	t.Run("clears all metrics", func(t *testing.T) {
		collector := newTestCollector(t)
		collector.Inc("key1", "metric1", "count", nil)
		collector.Inc("key2", "metric2", "count", nil)
		collector.Set("key3", "metric3", "gauge", 42, nil)

		collector.Reset()

		assert.Equal(t, 0, collector.cache.Size())
	})
}

func TestMetricsService_GetSnapshot(t *testing.T) {
	t.Run("returns a snapshot of the current cache", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func(*MetricsService)
			want  map[string]Metric
		}{
			{
				name: "with metrics",
				setup: func(c *MetricsService) {
					c.Inc("key1", "metric1", "count", map[string]string{"origin": "capi"})
					c.Set("key2", "metric2", "gauge", 42, nil)
				},
				want: map[string]Metric{
					"key1": {
						Name:   "metric1",
						Unit:   "count",
						Value:  1,
						Labels: map[string]string{"origin": "capi"},
					},
					"key2": {
						Name:   "metric2",
						Unit:   "gauge",
						Value:  42,
						Labels: nil,
					},
				},
			},
			{
				name:  "empty cache",
				setup: func(c *MetricsService) {},
				want:  map[string]Metric{},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				collector := newTestCollector(t)
				tt.setup(collector)

				got := collector.GetSnapshot()

				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("snapshot is independent of cache", func(t *testing.T) {
		collector := newTestCollector(t)
		collector.Inc("key1", "metric1", "count", nil)

		snapshot := collector.GetSnapshot()
		collector.Inc("key2", "metric2", "count", nil)

		want := map[string]Metric{
			"key1": {
				Name:   "metric1",
				Unit:   "count",
				Value:  1,
				Labels: nil,
			},
		}
		assert.Equal(t, want, snapshot)
	})
}

func TestMetricsService_Calculate(t *testing.T) {
	t.Run("builds complete metrics payload", func(t *testing.T) {
		collector := newStaticCollector(t)
		collector.Inc("requests", "http_requests_total", "count", map[string]string{"origin": "capi"})
		collector.Set("active", "active_connections", "gauge", 5, nil)

		got := collector.Calculate(30 * time.Second)
		component := got.RemediationComponents[0]
		require.NotNil(t, component.Os)
		require.NotNil(t, component.Metrics[0].Meta.UtcNowTimestamp)
		component.Metrics[0].Meta.UtcNowTimestamp = nil

		items := []*models.MetricsDetailItem{
			{
				Name:   new("active_connections"),
				Unit:   new("gauge"),
				Value:  new(float64(5)),
				Labels: nil,
			},
			{
				Name:   new("http_requests_total"),
				Unit:   new("count"),
				Value:  new(float64(1)),
				Labels: map[string]string{"origin": "capi"},
			},
		}
		sortItems(items)
		sortItems(component.Metrics[0].Items)

		want := wantMetrics(component, 30*time.Second, items)

		assert.Equal(t, want, got)
	})

	t.Run("handles empty metrics", func(t *testing.T) {
		collector := newStaticCollector(t)

		got := collector.Calculate(10 * time.Second)
		component := got.RemediationComponents[0]
		require.NotNil(t, component.Os)
		require.NotNil(t, component.Metrics[0].Meta.UtcNowTimestamp)
		component.Metrics[0].Meta.UtcNowTimestamp = nil

		want := wantMetrics(component, 10*time.Second, nil)

		assert.Equal(t, want, got)
	})

	t.Run("startup timestamp remains constant across Calculate calls", func(t *testing.T) {
		collector := newStaticCollector(t)
		collector.Inc("test", "test_metric", "count", nil)

		first := collector.Calculate(10 * time.Second)
		firstComponent := first.RemediationComponents[0]
		require.NotNil(t, firstComponent.Os)
		require.NotNil(t, firstComponent.Metrics[0].Meta.UtcNowTimestamp)
		firstComponent.Metrics[0].Meta.UtcNowTimestamp = nil

		collector.Inc("test", "test_metric", "count", nil)
		second := collector.Calculate(20 * time.Second)
		secondComponent := second.RemediationComponents[0]
		require.NotNil(t, secondComponent.Os)
		require.NotNil(t, secondComponent.Metrics[0].Meta.UtcNowTimestamp)
		secondComponent.Metrics[0].Meta.UtcNowTimestamp = nil

		wantFirst := wantMetrics(firstComponent, 10*time.Second, []*models.MetricsDetailItem{
			{
				Name:   new("test_metric"),
				Unit:   new("count"),
				Value:  new(float64(1)),
				Labels: nil,
			},
		})
		wantSecond := wantMetrics(secondComponent, 20*time.Second, []*models.MetricsDetailItem{
			{
				Name:   new("test_metric"),
				Unit:   new("count"),
				Value:  new(float64(2)),
				Labels: nil,
			},
		})

		assert.Equal(t, wantFirst, first)
		assert.Equal(t, wantSecond, second)
	})
}

func wantMetrics(component *models.RemediationComponentsMetrics, interval time.Duration, items []*models.MetricsDetailItem) *models.AllMetrics {
	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{
			{
				Type: "envoy-proxy",
				BaseMetrics: models.BaseMetrics{
					Os:                  component.Os,
					Version:             new("v1.0.0"),
					FeatureFlags:        []string{},
					UtcStartupTimestamp: new(staticStartupTS),
					Metrics: []*models.DetailedMetrics{
						{
							Meta:  &models.MetricsMeta{WindowSizeSeconds: new(int64(interval.Seconds()))},
							Items: items,
						},
					},
				},
			},
		},
	}
}

func TestMetricsService_Send(t *testing.T) {
	t.Run("sends metrics successfully", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := newMockCollector(t, mockClient)

		allMetrics := &models.AllMetrics{}
		ctx := t.Context()

		mockClient.EXPECT().SendMetrics(gomock.Any(), allMetrics).Return(nil)

		err := collector.Send(ctx, allMetrics)

		assert.Nil(t, err)
	})

	t.Run("returns error when send fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := newMockCollector(t, mockClient)

		allMetrics := &models.AllMetrics{}
		ctx := t.Context()
		wantErr := errors.New("network error")

		mockClient.EXPECT().SendMetrics(gomock.Any(), allMetrics).Return(wantErr)

		got := collector.Send(ctx, allMetrics)

		assert.Equal(t, wantErr, got)
	})

	t.Run("respects context timeout", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := newMockCollector(t, mockClient)

		allMetrics := &models.AllMetrics{}
		ctx := t.Context()

		mockClient.EXPECT().SendMetrics(gomock.Any(), allMetrics).DoAndReturn(
			func(ctx context.Context, metrics *models.AllMetrics) error {
				_, ok := ctx.Deadline()
				require.True(t, ok)
				return nil
			},
		)

		err := collector.Send(ctx, allMetrics)

		assert.Nil(t, err)
	})
}

func TestMetricsService_Run(t *testing.T) {
	t.Run("returns early without ticking", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(t.Context())
		cancel()

		tests := []struct {
			name     string
			interval time.Duration
			ctx      context.Context
			want     error
		}{
			{name: "interval is zero", interval: 0, ctx: t.Context(), want: nil},
			{name: "context already cancelled", interval: 10 * time.Millisecond, ctx: cancelledCtx, want: context.Canceled},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				collector := newTestCollector(t)

				got := collector.Run(tt.ctx, tt.interval)

				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("sends metrics and resets on successful tick", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := newTestCollector(t)
		collector.apiClient = mockClient
		collector.Inc("test", "test_metric", "count", nil)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		mockClient.EXPECT().SendMetrics(gomock.Any(), gomock.Any()).Return(nil).MinTimes(1)

		got := collector.Run(ctx, 20*time.Millisecond)

		assert.Equal(t, context.DeadlineExceeded, got)
		assert.Equal(t, 0, collector.cache.Size())
	})

	t.Run("does not reset when send fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := newTestCollector(t)
		collector.apiClient = mockClient
		collector.Inc("test", "test_metric", "count", nil)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		sendErr := errors.New("send failed")
		mockClient.EXPECT().SendMetrics(gomock.Any(), gomock.Any()).Return(sendErr).MinTimes(1)

		got := collector.Run(ctx, 20*time.Millisecond)

		assert.Equal(t, context.DeadlineExceeded, got)
		assert.Equal(t, 1, collector.cache.Size())
	})
}
