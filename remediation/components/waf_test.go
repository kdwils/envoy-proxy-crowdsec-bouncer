package components

import (
	bytes "bytes"
	"context"
	errors "errors"
	io "io"
	nethttp "net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	mocks "github.com/kdwils/envoy-proxy-bouncer/remediation/components/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestBuildAppSecHeaders(t *testing.T) {
	realIP := "192.168.1.1"
	uri := "/test/uri"
	host := "example.com"
	method := "POST"
	apiKey := "test-api-key"
	userAgent := "Go-http-client/1.1"
	httpVersion := "1.1"

	expected := map[string]string{
		"X-Crowdsec-Appsec-Ip":           realIP,
		"X-Crowdsec-Appsec-Uri":          uri,
		"X-Crowdsec-Appsec-Host":         host,
		"X-Crowdsec-Appsec-Verb":         method,
		"X-Crowdsec-Appsec-Api-Key":      apiKey,
		"X-Crowdsec-Appsec-User-Agent":   userAgent,
		"X-Crowdsec-Appsec-Http-Version": httpVersion,
	}

	got := buildAppSecHeaders(realIP, uri, host, method, apiKey, userAgent, httpVersion)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("buildAppSecHeaders() = %v, want %v", got, expected)
	}
}

func TestBuildAppSecHeaders_EmptyValues(t *testing.T) {
	expected := map[string]string{
		"X-Crowdsec-Appsec-Ip":           "",
		"X-Crowdsec-Appsec-Uri":          "",
		"X-Crowdsec-Appsec-Host":         "",
		"X-Crowdsec-Appsec-Verb":         "",
		"X-Crowdsec-Appsec-Api-Key":      "",
		"X-Crowdsec-Appsec-User-Agent":   "",
		"X-Crowdsec-Appsec-Http-Version": "",
	}

	got := buildAppSecHeaders("", "", "", "", "", "", "")

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("buildAppSecHeaders() with empty values = %v, want %v", got, expected)
	}
}

func TestWAF_Inspect(t *testing.T) {
	t.Run("error on request build", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockCrowdsecClient(ctrl)
		// WAF with invalid URL should fail before making HTTP call
		waf := WAF{Enabled: true, APIURL: ":badurl", http: mockHTTP}
		ctx := context.Background()
		req, _ := nethttp.NewRequest("GET", "http://example.com", nil)
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockCrowdsecClient(ctrl)
		waf := WAF{Enabled: true, APIURL: "http://test", http: mockHTTP}
		mockHTTP.EXPECT().Do(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("fail")).Times(1)
		req, _ := nethttp.NewRequest("GET", "http://localhost/test", nil)
		ctx := context.Background()
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockCrowdsecClient(ctrl)
		waf := WAF{Enabled: true, APIURL: "http://test", http: mockHTTP}
		response := &nethttp.Response{StatusCode: 500, Status: "500 error", Body: io.NopCloser(strings.NewReader(""))}
		resp := &apiclient.Response{Response: response}
		mockHTTP.EXPECT().Do(gomock.Any(), gomock.Any(), gomock.Any()).Return(resp, nil).Times(1)
		req, _ := nethttp.NewRequest("GET", "http://localhost/test", nil)
		ctx := context.Background()
		_, err := waf.Inspect(ctx, req, "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockCrowdsecClient(ctrl)
		waf := WAF{Enabled: true, APIURL: "http://test", APIKey: "key", http: mockHTTP}
		respBody := `{"action":"ban","http_status":403}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		resp := &apiclient.Response{Response: response}
		mockHTTP.EXPECT().Do(gomock.Any(), gomock.Any(), gomock.Any()).Return(resp, nil).Times(1)
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
		mockHTTP := mocks.NewMockCrowdsecClient(ctrl)
		waf := WAF{Enabled: true, APIURL: "http://test", APIKey: "key", http: mockHTTP}
		respBody := `{"action":"captcha"}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		resp := &apiclient.Response{Response: response}
		mockHTTP.EXPECT().Do(gomock.Any(), gomock.Any(), gomock.Any()).Return(resp, nil).Times(1)
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
