package crowdsec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
	"github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec/mocks"
)

func TestNewMetricsService(t *testing.T) {
	t.Run("creates collector with valid config", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}

		collector, err := NewMetricsService(cfg)

		require.Nil(t, err)
		require.NotNil(t, collector)
		require.NotNil(t, collector.cache)
		require.NotNil(t, collector.apiClient)
		assert.Equal(t, "envoy-proxy", collector.bouncerType)
		assert.Equal(t, "v1.0.0", collector.version)
	})

	t.Run("returns error when api client is nil", func(t *testing.T) {
		cfg := MetricsConfig{
			APIClient:   nil,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}

		collector, err := NewMetricsService(cfg)

		wantErr := "api client is required"
		assert.Equal(t, wantErr, err.Error())
		assert.Nil(t, collector)
	})

	t.Run("returns error when bouncer type is empty", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "",
			Version:     "v1.0.0",
		}

		collector, err := NewMetricsService(cfg)

		wantErr := "bouncer type is required"
		assert.Equal(t, wantErr, err.Error())
		assert.Nil(t, collector)
	})

	t.Run("returns error when version is empty", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "",
		}

		collector, err := NewMetricsService(cfg)

		wantErr := "version is required"
		assert.Equal(t, wantErr, err.Error())
		assert.Nil(t, collector)
	})
}

func TestMetricsService_Inc(t *testing.T) {
	t.Run("increments new metric", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Inc("test_key", "test_metric", "count", labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "count",
			Value:  1,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("increments existing metric", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Inc("test_key", "test_metric", "count", labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "count",
			Value:  3,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("increments multiple different metrics", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Inc("key1", "metric1", "count", map[string]string{"type": "a"})
		collector.Inc("key2", "metric2", "count", map[string]string{"type": "b"})

		got1, ok1 := collector.cache.Get("key1")
		require.True(t, ok1)
		want1 := Metric{
			Name:   "metric1",
			Unit:   "count",
			Value:  1,
			Labels: map[string]string{"type": "a"},
		}
		assert.Equal(t, want1, got1)

		got2, ok2 := collector.cache.Get("key2")
		require.True(t, ok2)
		want2 := Metric{
			Name:   "metric2",
			Unit:   "count",
			Value:  1,
			Labels: map[string]string{"type": "b"},
		}
		assert.Equal(t, want2, got2)
	})
}

func TestMetricsService_Dec(t *testing.T) {
	t.Run("decrements existing metric", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Inc("test_key", "test_metric", "count", labels)

		collector.Dec("test_key", "test_metric", "count", labels)

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

	t.Run("decrements new metric to zero", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Dec("test_key", "test_metric", "count", labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "count",
			Value:  0,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("does not go below zero", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Inc("test_key", "test_metric", "count", labels)
		collector.Dec("test_key", "test_metric", "count", labels)
		collector.Dec("test_key", "test_metric", "count", labels)
		collector.Dec("test_key", "test_metric", "count", labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		assert.Equal(t, int64(0), got.Value)
	})
}

func TestMetricsService_Set(t *testing.T) {
	t.Run("sets new metric", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Set("test_key", "test_metric", "gauge", 42, labels)

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

	t.Run("overwrites existing metric", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		labels := map[string]string{"origin": "capi"}
		collector.Set("test_key", "test_metric", "gauge", 42, labels)
		collector.Set("test_key", "test_metric", "gauge", 100, labels)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "gauge",
			Value:  100,
			Labels: map[string]string{"origin": "capi"},
		}
		assert.Equal(t, want, got)
	})

	t.Run("sets zero value", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Set("test_key", "test_metric", "gauge", 0, nil)

		got, ok := collector.cache.Get("test_key")
		require.True(t, ok)

		want := Metric{
			Name:   "test_metric",
			Unit:   "gauge",
			Value:  0,
			Labels: nil,
		}
		assert.Equal(t, want, got)
	})
}

func TestMetricsService_Reset(t *testing.T) {
	t.Run("clears all metrics", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Inc("key1", "metric1", "count", nil)
		collector.Inc("key2", "metric2", "count", nil)
		collector.Set("key3", "metric3", "gauge", 42, nil)

		assert.Equal(t, 3, collector.cache.Size())

		collector.Reset()

		assert.Equal(t, 0, collector.cache.Size())

		_, ok1 := collector.cache.Get("key1")
		assert.False(t, ok1)

		_, ok2 := collector.cache.Get("key2")
		assert.False(t, ok2)

		_, ok3 := collector.cache.Get("key3")
		assert.False(t, ok3)
	})

	t.Run("reset on empty cache", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Reset()

		assert.Equal(t, 0, collector.cache.Size())
	})
}

func TestMetricsService_GetSnapshot(t *testing.T) {
	t.Run("returns snapshot of all metrics", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Inc("key1", "metric1", "count", map[string]string{"origin": "capi"})
		collector.Set("key2", "metric2", "gauge", 42, nil)

		got := collector.GetSnapshot()

		want := map[string]Metric{
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
		}
		assert.Equal(t, want, got)
	})

	t.Run("returns empty map for empty cache", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		got := collector.GetSnapshot()

		want := map[string]Metric{}
		assert.Equal(t, want, got)
	})

	t.Run("snapshot is independent of cache", func(t *testing.T) {
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)

		collector.Inc("key1", "metric1", "count", nil)
		snapshot := collector.GetSnapshot()

		collector.Inc("key2", "metric2", "count", nil)

		assert.Equal(t, 1, len(snapshot))
		assert.Equal(t, 2, collector.cache.Size())
	})
}

func TestMetricsService_Calculate(t *testing.T) {
	t.Run("calculates metrics with correct structure", func(t *testing.T) {
		staticStartupTS := int64(1234567890)
		collector := &MetricsService{
			cache:       cache.New[Metric](),
			apiClient:   &crowdSecClient{client: &apiclient.ApiClient{}},
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
			startupTS:   staticStartupTS,
		}

		collector.Inc("processed", "http_requests_total", "count", map[string]string{"origin": "capi"})
		collector.Set("active", "active_connections", "gauge", 5, nil)

		interval := 30 * time.Second
		allMetrics := collector.Calculate(interval)

		require.NotNil(t, allMetrics)
		require.NotNil(t, allMetrics.RemediationComponents)
		require.Equal(t, 1, len(allMetrics.RemediationComponents))

		component := allMetrics.RemediationComponents[0]
		assert.Equal(t, "envoy-proxy", component.Type)
		assert.Equal(t, "v1.0.0", *component.Version)
		require.Equal(t, 1, len(component.Metrics))

		meta := component.Metrics[0].Meta
		assert.Equal(t, int64(30), *meta.WindowSizeSeconds)

		items := component.Metrics[0].Items
		assert.Equal(t, 2, len(items))

		require.NotNil(t, component.UtcStartupTimestamp)
		assert.Equal(t, staticStartupTS, *component.UtcStartupTimestamp)
	})

	t.Run("includes all metric details", func(t *testing.T) {
		staticStartupTS := int64(1234567890)
		collector := &MetricsService{
			cache:       cache.New[Metric](),
			apiClient:   &crowdSecClient{client: &apiclient.ApiClient{}},
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
			startupTS:   staticStartupTS,
		}

		labels := map[string]string{"origin": "capi", "type": "ban"}
		collector.Inc("test_metric", "decisions_applied", "count", labels)

		allMetrics := collector.Calculate(10 * time.Second)

		items := allMetrics.RemediationComponents[0].Metrics[0].Items
		require.Equal(t, 1, len(items))

		got := items[0]
		want := &models.MetricsDetailItem{
			Name:   ptr("decisions_applied"),
			Unit:   ptr("count"),
			Value:  ptr(float64(1)),
			Labels: map[string]string{"origin": "capi", "type": "ban"},
		}
		assert.Equal(t, want, got)

		component := allMetrics.RemediationComponents[0]
		require.NotNil(t, component.UtcStartupTimestamp)
		assert.Equal(t, staticStartupTS, *component.UtcStartupTimestamp)
	})

	t.Run("handles empty metrics", func(t *testing.T) {
		staticStartupTS := int64(1234567890)
		collector := &MetricsService{
			cache:       cache.New[Metric](),
			apiClient:   &crowdSecClient{client: &apiclient.ApiClient{}},
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
			startupTS:   staticStartupTS,
		}

		allMetrics := collector.Calculate(10 * time.Second)

		require.NotNil(t, allMetrics)
		require.NotNil(t, allMetrics.RemediationComponents)

		items := allMetrics.RemediationComponents[0].Metrics[0].Items
		assert.Equal(t, 0, len(items))

		component := allMetrics.RemediationComponents[0]
		require.NotNil(t, component.UtcStartupTimestamp)
		assert.Equal(t, staticStartupTS, *component.UtcStartupTimestamp)
	})

	t.Run("startup timestamp remains constant across multiple Calculate calls", func(t *testing.T) {
		staticStartupTS := int64(1234567890)
		collector := &MetricsService{
			cache:       cache.New[Metric](),
			apiClient:   &crowdSecClient{client: &apiclient.ApiClient{}},
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
			startupTS:   staticStartupTS,
		}

		collector.Inc("test", "test_metric", "count", nil)

		firstMetrics := collector.Calculate(10 * time.Second)
		firstComponent := firstMetrics.RemediationComponents[0]
		require.NotNil(t, firstComponent.UtcStartupTimestamp)
		assert.Equal(t, staticStartupTS, *firstComponent.UtcStartupTimestamp)

		time.Sleep(10 * time.Millisecond)

		collector.Inc("test", "test_metric", "count", nil)

		secondMetrics := collector.Calculate(20 * time.Second)
		secondComponent := secondMetrics.RemediationComponents[0]
		require.NotNil(t, secondComponent.UtcStartupTimestamp)
		assert.Equal(t, staticStartupTS, *secondComponent.UtcStartupTimestamp)

		assert.Equal(t, *firstComponent.UtcStartupTimestamp, *secondComponent.UtcStartupTimestamp)
	})
}

func TestMetricsService_Send(t *testing.T) {
	t.Run("sends metrics successfully", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := &MetricsService{
			apiClient:   mockClient,
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
		}

		allMetrics := &models.AllMetrics{}
		ctx := context.Background()

		mockClient.EXPECT().SendMetrics(gomock.Any(), allMetrics).Return(nil)

		err := collector.Send(ctx, allMetrics)

		assert.Nil(t, err)
	})

	t.Run("returns error when send fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := &MetricsService{
			apiClient:   mockClient,
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
		}

		allMetrics := &models.AllMetrics{}
		ctx := context.Background()
		wantErr := errors.New("network error")

		mockClient.EXPECT().SendMetrics(gomock.Any(), allMetrics).Return(wantErr)

		got := collector.Send(ctx, allMetrics)

		assert.Equal(t, wantErr, got)
	})

	t.Run("respects context timeout", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := &MetricsService{
			apiClient:   mockClient,
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
		}

		allMetrics := &models.AllMetrics{}
		ctx := context.Background()

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
	t.Run("returns immediately when interval is zero", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := &MetricsService{
			apiClient:   mockClient,
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
		}

		ctx := context.Background()
		err := collector.Run(ctx, 0)

		assert.Nil(t, err)
	})

	t.Run("stops when context is cancelled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		collector := &MetricsService{
			apiClient:   mockClient,
			bouncerType: "envoy-proxy",
			version:     "v1.0.0",
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got := collector.Run(ctx, 10*time.Millisecond)

		want := context.Canceled
		assert.Equal(t, want, got)
	})

	t.Run("sends metrics and resets on successful tick", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)
		collector.apiClient = mockClient

		collector.Inc("test", "test_metric", "count", nil)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		mockClient.EXPECT().SendMetrics(gomock.Any(), gomock.Any()).Return(nil).MinTimes(1)

		got := collector.Run(ctx, 20*time.Millisecond)

		want := context.DeadlineExceeded
		assert.Equal(t, want, got)
	})

	t.Run("does not reset when send fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := mocks.NewMockCrowdsecClient(ctrl)
		client := &apiclient.ApiClient{}
		cfg := MetricsConfig{
			APIClient:   client,
			BouncerType: "envoy-proxy",
			Version:     "v1.0.0",
		}
		collector, err := NewMetricsService(cfg)
		require.Nil(t, err)
		collector.apiClient = mockClient

		collector.Inc("test", "test_metric", "count", nil)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		sendErr := errors.New("send failed")
		mockClient.EXPECT().SendMetrics(gomock.Any(), gomock.Any()).Return(sendErr).MinTimes(1)

		got := collector.Run(ctx, 20*time.Millisecond)

		want := context.DeadlineExceeded
		assert.Equal(t, want, got)
	})
}
