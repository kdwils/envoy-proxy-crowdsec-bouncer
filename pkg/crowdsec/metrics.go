package crowdsec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/kdwils/envoy-proxy-bouncer/pkg/cache"
)

// Metric represents a single metric data point with associated metadata.
type Metric struct {
	Name   string
	Unit   string
	Value  int64
	Labels map[string]string
}

//go:generate mockgen -destination=mocks/mock_api_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/pkg/crowdsec CrowdsecClient

// CrowdsecClient defines the interface for sending metrics to CrowdSec.
type CrowdsecClient interface {
	SendMetrics(ctx context.Context, metrics *models.AllMetrics) error
}

type crowdSecClient struct {
	client *apiclient.ApiClient
}

func (c *crowdSecClient) SendMetrics(ctx context.Context, metrics *models.AllMetrics) error {
	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, resp, err := c.client.UsageMetrics.Add(ctxTime, metrics)
	if err != nil {
		return err
	}

	if resp.Response == nil {
		return errors.New("nil response")
	}

	if resp.Response.StatusCode > http.StatusCreated {
		return fmt.Errorf("unexpected status: %s", resp.Response.Status)
	}

	return nil
}

// MetricsService manages the collection, aggregation, and transmission of metrics to CrowdSec.
// It maintains an internal cache of metrics and periodically sends them to the CrowdSec API.
//
// When using Run to start automatic metric reporting, users should only call Inc, Dec, and Set
// to update metrics. The Run method handles all Calculate, Send, and Reset operations automatically.
type MetricsService struct {
	cache       *cache.Cache[Metric]
	apiClient   CrowdsecClient
	bouncerType string
	version     string
	startupTS   int64
}

// MetricsConfig holds the configuration required to create a new MetricsService.
type MetricsConfig struct {
	APIClient   *apiclient.ApiClient
	BouncerType string
	Version     string
}

// NewMetricsService creates and initializes a new MetricsService instance.
func NewMetricsService(cfg MetricsConfig) (*MetricsService, error) {
	if cfg.APIClient == nil {
		return nil, errors.New("api client is required")
	}
	if cfg.BouncerType == "" {
		return nil, errors.New("bouncer type is required")
	}
	if cfg.Version == "" {
		return nil, errors.New("version is required")
	}

	return &MetricsService{
		cache:       cache.New[Metric](),
		apiClient:   &crowdSecClient{client: cfg.APIClient},
		bouncerType: cfg.BouncerType,
		version:     cfg.Version,
		startupTS:   time.Now().UTC().Unix(),
	}, nil
}

// Inc increments the value of a metric by 1.
// If the metric does not exist, it creates a new metric with value 1.
// The key is used to uniquely identify the metric in the cache.
func (mc *MetricsService) Inc(key string, name string, unit string, labels map[string]string) {
	metric, exists := mc.cache.Get(key)
	if !exists {
		metric = Metric{
			Name:   name,
			Unit:   unit,
			Value:  0,
			Labels: labels,
		}
	}
	metric.Value++
	mc.cache.Set(key, metric)
}

// Dec decrements the value of a metric by 1.
// If the metric does not exist, it creates a new metric with value 0.
// The value is clamped at 0 and will never go negative.
// The key is used to uniquely identify the metric in the cache.
func (mc *MetricsService) Dec(key string, name string, unit string, labels map[string]string) {
	metric, exists := mc.cache.Get(key)
	if !exists {
		metric = Metric{
			Name:   name,
			Unit:   unit,
			Value:  0,
			Labels: labels,
		}
	}
	metric.Value--
	if metric.Value < 0 {
		metric.Value = 0
	}
	mc.cache.Set(key, metric)
}

// Set sets the value of a metric to a specific value.
// If the metric already exists, it will be overwritten.
// The key is used to uniquely identify the metric in the cache.
func (mc *MetricsService) Set(key string, name string, unit string, value int64, labels map[string]string) {
	metric := Metric{
		Name:   name,
		Unit:   unit,
		Value:  value,
		Labels: labels,
	}
	mc.cache.Set(key, metric)
}

// Reset clears all metrics from the internal cache.
// This is typically called automatically after successfully sending metrics to CrowdSec.
// Users should not call this method when using Run, as it handles resetting automatically.
func (mc *MetricsService) Reset() {
	for _, k := range mc.cache.Keys() {
		mc.cache.Delete(k)
	}
}

// GetSnapshot returns a copy of all current metrics in the cache.
// The returned map is a snapshot and modifications will not affect the internal cache.
func (mc *MetricsService) GetSnapshot() map[string]Metric {
	snapshot := make(map[string]Metric)
	for _, key := range mc.cache.Keys() {
		metric, exists := mc.cache.Get(key)
		if exists {
			snapshot[key] = metric
		}
	}
	return snapshot
}

// Calculate transforms the current metrics snapshot into the CrowdSec AllMetrics format.
// The interval parameter specifies the time window over which these metrics were collected.
// This method includes system information and metadata required by the CrowdSec API.
// Users should not call this method when using Run, as it handles calculation automatically.
func (mc *MetricsService) Calculate(interval time.Duration) *models.AllMetrics {
	currentMetrics := mc.GetSnapshot()

	var items []*models.MetricsDetailItem

	for _, metric := range currentMetrics {
		items = append(items, &models.MetricsDetailItem{
			Name:   ptr(metric.Name),
			Unit:   ptr(metric.Unit),
			Value:  ptr(float64(metric.Value)),
			Labels: metric.Labels,
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

	osName, osVersion := version.DetectOS()

	baseMetrics := &models.BaseMetrics{
		Os: &models.OSversion{
			Name:    &osName,
			Version: &osVersion,
		},
		Version:             &mc.version,
		FeatureFlags:        []string{},
		Metrics:             detailedMetrics,
		UtcStartupTimestamp: &mc.startupTS,
	}

	remediationMetrics := &models.RemediationComponentsMetrics{
		BaseMetrics: *baseMetrics,
		Type:        mc.bouncerType,
	}

	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{remediationMetrics},
	}
}

// Send transmits the provided metrics to the CrowdSec API.
// The operation has a timeout of 10 seconds.
// Users should not call this method when using Run, as it handles sending automatically.
func (mc *MetricsService) Send(ctx context.Context, metrics *models.AllMetrics) error {
	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return mc.apiClient.SendMetrics(ctxTime, metrics)
}

// Run periodically calculates and sends metrics to CrowdSec at the specified interval.
// It sends metrics and resets the cache on successful transmission.
// If interval is 0, the method returns immediately without starting the loop.
//
// The method blocks until the context is canceled and returns the context error.
//
// This method should be called in a goroutine to run in the background:
//
//	go metricsService.Run(ctx, 30*time.Second)
//
// When using Run, users should only call Inc, Dec, and Set to update metrics.
// The Run method automatically handles calling Calculate, Send, and Reset at each interval.
func (mc *MetricsService) Run(ctx context.Context, interval time.Duration) error {
	if interval == 0 {
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			allMetrics := mc.Calculate(interval)
			if err := mc.Send(ctx, allMetrics); err == nil {
				mc.Reset()
			}
		}
	}
}

func ptr[T any](v T) *T {
	return &v
}
