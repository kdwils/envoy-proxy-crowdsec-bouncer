package components

import (
	bytes "bytes"
	"context"
	errors "errors"
	io "io"
	nethttp "net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	mocks "github.com/kdwils/envoy-proxy-bouncer/remediation/components/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestBuildAppSecHeaders(t *testing.T) {
	req := &nethttp.Request{
		Header: nethttp.Header{
			"User-Agent": []string{"Go-http-client/1.1"},
		},
		URL: &url.URL{
			Path: "/test/uri",
			Host: "example.com",
		},
		Method: "POST",
		Proto:  "HTTP/1.1",
	}
	realIP := "192.168.1.1"
	apiKey := "test-api-key"
	userAgent := "Go-http-client/1.1"

	expected := map[string]string{
		"X-Crowdsec-Appsec-Ip":           realIP,
		"X-Crowdsec-Appsec-Uri":          req.URL.Path,
		"X-Crowdsec-Appsec-Host":         req.URL.Host,
		"X-Crowdsec-Appsec-Verb":         req.Method,
		"X-Crowdsec-Appsec-Api-Key":      apiKey,
		"X-Crowdsec-Appsec-User-Agent":   userAgent,
		"X-Crowdsec-Appsec-Http-Version": req.Proto,
	}

	got := buildAppSecHeaders(req, realIP, apiKey)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("buildAppSecHeaders() = %v, want %v", got, expected)
	}
}

func TestWAF_Inspect(t *testing.T) {
	t.Run("error on request build", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		// WAF with invalid URL should fail before making HTTP call
		waf := WAF{APIURL: ":badurl", http: mockHTTP}
		ctx := context.Background()
		req, _ := nethttp.NewRequest("GET", "http://example.com", nil)
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", http: mockHTTP}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(nil, errors.New("fail")).Times(1)
		req, _ := nethttp.NewRequest("GET", "http://localhost/test", nil)
		ctx := context.Background()
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", http: mockHTTP}
		response := &nethttp.Response{StatusCode: 500, Status: "500 error", Body: io.NopCloser(strings.NewReader(""))}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(response, nil).Times(1)
		req, _ := nethttp.NewRequest("GET", "http://localhost/test", nil)
		ctx := context.Background()
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", APIKey: "key", http: mockHTTP}
		respBody := `{"action":"ban","http_status":403}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(response, nil).Times(1)
		req, _ := nethttp.NewRequest("GET", "http://example.com/foo", nil)
		req.Host = "example.com"
		req.Header.Set("User-Agent", "test-agent")
		ctx := context.Background()
		result, err := waf.Inspect(ctx, req, "1.2.3.4")
		assert.NoError(t, err)
		assert.Equal(t, "ban", result.Action)
		assert.Equal(t, 403, result.HTTPStatus)
	})

	t.Run("with body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", APIKey: "key", http: mockHTTP}
		respBody := `{"action":"captcha"}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(response, nil).Times(1)
		req, _ := nethttp.NewRequest("POST", "http://example.com/foo", bytes.NewReader([]byte("test")))
		req.Host = "example.com"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "test-agent")
		ctx := context.Background()
		result, err := waf.Inspect(ctx, req, "1.2.3.4")
		assert.NoError(t, err)
		assert.Equal(t, "captcha", result.Action)
	})
}
