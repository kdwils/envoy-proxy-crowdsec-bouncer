package components

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type MetricsProvider struct {
	APIClient *apiclient.ApiClient
}

func NewMetricsProvider(client *apiclient.ApiClient) (*MetricsProvider, error) {
	return &MetricsProvider{
		APIClient: client,
	}, nil
}

func (m *MetricsProvider) SendMetrics(ctx context.Context, metrics *models.AllMetrics) error {
	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, resp, err := m.APIClient.UsageMetrics.Add(ctxTime, metrics)
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

