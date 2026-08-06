package components

import (
	"context"
	errors "errors"
	io "io"
	nethttp "net/http"
	"net/url"
	"strings"
	"testing"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// httpReqMatcher validates the HTTP request sent to AppSec matches expectations.
type httpReqMatcher struct {
	method  string
	urlStr  string
	headers map[string]string // subset to verify
}

func (m httpReqMatcher) Matches(x any) bool {
	r, ok := x.(*nethttp.Request)
	if !ok || r == nil {
		return false
	}
	if m.method != "" && r.Method != m.method {
		return false
	}
	if m.urlStr != "" && r.URL.String() != m.urlStr {
		return false
	}
	for k, v := range m.headers {
		if got := r.Header.Get(k); got != v {
			return false
		}
	}
	return true
}

func (m httpReqMatcher) String() string { return "httpReqMatcher" }

func TestNewForwardRequest(t *testing.T) {
	ctx := context.Background()
	apiURL, err := url.Parse("http://crowdsec:8080/v1/")
	assert.NoError(t, err)

	t.Run("get request builds appsec headers", func(t *testing.T) {
		areq := AppSecRequest{
			Method: "GET",
			URL:    url.URL{Path: "/test", Host: "example.com"},
			Headers: map[string]string{
				"user-agent":     "test-agent",
				"Content-Type":   "application/json",
				":pseudo-header": "skipped",
			},
			RealIP:     "1.2.3.4",
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		r := newForwardRequest(ctx, apiURL, areq, "key")

		assert.Equal(t, nethttp.MethodGet, r.Method)
		assert.Equal(t, apiURL, r.URL)
		assert.Equal(t, apiURL.Host, r.Host)
		assert.Equal(t, nethttp.NoBody, r.Body)
		assert.Equal(t, ctx, r.Context())

		expected := map[string]string{
			"X-Crowdsec-Appsec-Ip":           "1.2.3.4",
			"X-Crowdsec-Appsec-Uri":          "/test",
			"X-Crowdsec-Appsec-Host":         "example.com",
			"X-Crowdsec-Appsec-Verb":         "GET",
			"X-Crowdsec-Appsec-Api-Key":      "key",
			"X-Crowdsec-Appsec-User-Agent":   "test-agent",
			"X-Crowdsec-Appsec-Http-Version": "11",
			"Content-Type":                   "application/json",
			"User-Agent":                     "test-agent",
		}
		for k, want := range expected {
			assert.Equal(t, want, r.Header.Get(k), "header %q", k)
		}
		_, hasPseudo := r.Header[":pseudo-header"]
		assert.False(t, hasPseudo)
	})

	t.Run("post request copies body and sets content length", func(t *testing.T) {
		areq := AppSecRequest{
			Method: "POST",
			URL:    url.URL{Path: "/test", Host: "example.com"},
			Headers: map[string]string{"user-agent": "test-agent"},
			Body:   []byte("test"),
			RealIP: "1.2.3.4",
		}
		r := newForwardRequest(ctx, apiURL, areq, "key")

		assert.Equal(t, nethttp.MethodPost, r.Method)
		assert.Equal(t, int64(4), r.ContentLength)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, "test", string(body))

		body2, err := r.GetBody()
		assert.NoError(t, err)
		got, err := io.ReadAll(body2)
		assert.NoError(t, err)
		assert.Equal(t, "test", string(got))
	})

	t.Run("http version header omitted when proto major is zero", func(t *testing.T) {
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}}
		r := newForwardRequest(ctx, apiURL, areq, "key")
		assert.Empty(t, r.Header.Get("X-Crowdsec-Appsec-Http-Version"))
	})
}

func newTestWAF(appsecURL, apiKey string, http HTTPClient) WAF {
	u, err := url.Parse(appsecURL)
	if err != nil {
		panic(err)
	}
	return WAF{APIURL: appsecURL, apiURL: u, APIKey: apiKey, http: http}
}

func TestWAF_Inspect(t *testing.T) {
	t.Run("error on request build", func(t *testing.T) {
		_, err := NewWAF(":badurl", "", nethttp.DefaultClient)
		assert.Error(t, err)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		waf := newTestWAF("http://test", "", mockHTTP)
		expectedHeaders := map[string]string{
			"User-Agent":             "UA",
			"X-Crowdsec-Appsec-Ip":   "192.168.1.1",
			"X-Crowdsec-Appsec-Uri":  "/test",
			"X-Crowdsec-Appsec-Host": "localhost",
			"X-Crowdsec-Appsec-Verb": "GET",
		}
		mockHTTP.EXPECT().Do(httpReqMatcher{method: "GET", urlStr: "http://test", headers: expectedHeaders}).Return(nil, errors.New("fail")).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		ctx := context.Background()
		_, err := waf.Inspect(ctx, areq)
		assert.Error(t, err)
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		waf := newTestWAF("http://test", "", mockHTTP)
		response := &nethttp.Response{StatusCode: 500, Status: "500 error", Body: io.NopCloser(strings.NewReader(""))}
		expectedHeaders := map[string]string{
			"User-Agent":             "UA",
			"X-Crowdsec-Appsec-Ip":   "192.168.1.1",
			"X-Crowdsec-Appsec-Uri":  "/test",
			"X-Crowdsec-Appsec-Host": "localhost",
			"X-Crowdsec-Appsec-Verb": "GET",
		}
		mockHTTP.EXPECT().Do(httpReqMatcher{method: "GET", urlStr: "http://test", headers: expectedHeaders}).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		ctx := context.Background()
		_, err := waf.Inspect(ctx, areq)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		waf := newTestWAF("http://test", "key", mockHTTP)
		respBody := `{"action":"ban","http_status":403}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		expectedHeaders := map[string]string{
			"User-Agent":                   "test-agent",
			"X-Crowdsec-Appsec-Ip":         "1.2.3.4",
			"X-Crowdsec-Appsec-Uri":        "/foo",
			"X-Crowdsec-Appsec-Host":       "example.com",
			"X-Crowdsec-Appsec-Verb":       "GET",
			"X-Crowdsec-Appsec-Api-Key":    "key",
			"X-Crowdsec-Appsec-User-Agent": "test-agent",
		}
		mockHTTP.EXPECT().Do(httpReqMatcher{method: "GET", urlStr: "http://test", headers: expectedHeaders}).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		ctx := context.Background()
		result, err := waf.Inspect(ctx, areq)
		assert.NoError(t, err)
		assert.Equal(t, "ban", result.Action)
		assert.Equal(t, 403, result.HTTPStatus)
	})

	t.Run("with body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		waf := newTestWAF("http://test", "key", mockHTTP)
		respBody := `{"action":"captcha"}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		expectedHeaders := map[string]string{
			"User-Agent":                   "test-agent",
			"Content-Type":                 "application/json",
			"X-Crowdsec-Appsec-Ip":         "1.2.3.4",
			"X-Crowdsec-Appsec-Uri":        "/foo",
			"X-Crowdsec-Appsec-Host":       "example.com",
			"X-Crowdsec-Appsec-Verb":       "POST",
			"X-Crowdsec-Appsec-Api-Key":    "key",
			"X-Crowdsec-Appsec-User-Agent": "test-agent",
		}
		mockHTTP.EXPECT().Do(httpReqMatcher{method: "POST", urlStr: "http://test", headers: expectedHeaders}).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "POST", Headers: map[string]string{"Content-Type": "application/json", "user-agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}, Body: []byte("test")}
		ctx := context.Background()
		result, err := waf.Inspect(ctx, areq)
		assert.NoError(t, err)
		assert.Equal(t, "captcha", result.Action)
	})
}
