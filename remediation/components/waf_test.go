package components

import (
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
		Method:     "POST",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
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
		"X-Crowdsec-Appsec-Http-Version": "11",
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
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/"}}
		_, err := waf.Inspect(ctx, areq)
		assert.Error(t, err)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", http: mockHTTP}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(nil, errors.New("fail")).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		ctx := context.Background()
		_, err := waf.Inspect(ctx, areq)
		assert.Error(t, err)
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTP(ctrl)
		waf := WAF{APIURL: "http://test", http: mockHTTP}
		response := &nethttp.Response{StatusCode: 500, Status: "500 error", Body: io.NopCloser(strings.NewReader(""))}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		ctx := context.Background()
		_, err := waf.Inspect(ctx, areq)
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
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"User-Agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		ctx := context.Background()
		result, err := waf.Inspect(ctx, areq)
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
		areq := AppSecRequest{Method: "POST", Headers: map[string]string{"Content-Type": "application/json", "User-Agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}, Body: []byte("test")}
		ctx := context.Background()
		result, err := waf.Inspect(ctx, areq)
		assert.NoError(t, err)
		assert.Equal(t, "captcha", result.Action)
	})
}
