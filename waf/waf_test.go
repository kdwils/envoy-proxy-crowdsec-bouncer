package waf

import (
	"context"
	errors "errors"
	io "io"
	nethttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/config"
	mocks "github.com/kdwils/envoy-proxy-bouncer/types/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewForwardRequest(t *testing.T) {
	apiURL := url.URL{Scheme: "http", Host: "crowdsec:8080", Path: "/v1/"}

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
		r := newForwardRequest(t.Context(), apiURL, areq, "key")

		assert.Equal(t, nethttp.MethodGet, r.Method)
		require.NotNil(t, r.URL)
		assert.Equal(t, apiURL, *r.URL)
		assert.Equal(t, apiURL.Host, r.Host)
		assert.Equal(t, nethttp.NoBody, r.Body)
		assert.Equal(t, t.Context(), r.Context())

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
			Method:  "POST",
			URL:     url.URL{Path: "/test", Host: "example.com"},
			Headers: map[string]string{"user-agent": "test-agent"},
			Body:    []byte("test"),
			RealIP:  "1.2.3.4",
		}
		r := newForwardRequest(t.Context(), apiURL, areq, "key")

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
		r := newForwardRequest(t.Context(), apiURL, areq, "key")
		assert.Empty(t, r.Header.Get("X-Crowdsec-Appsec-Http-Version"))
	})
}

func TestWAF_Inspect(t *testing.T) {
	t.Run("error on request build", func(t *testing.T) {
		cfg := config.WAF{AppSecURL: ":badurl"}
		got, err := NewWAF(cfg, nil)
		assert.Error(t, err)
		assert.Equal(t, WAF{}, got)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", HTTPTimeout: time.Second}
		waf, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)
		expectedHeaders := map[string]string{
			"User-Agent":             "UA",
			"X-Crowdsec-Appsec-Ip":   "192.168.1.1",
			"X-Crowdsec-Appsec-Uri":  "/test",
			"X-Crowdsec-Appsec-Host": "localhost",
			"X-Crowdsec-Appsec-Verb": "GET",
		}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(nil, errors.New("fail")).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		_, err = waf.Inspect(t.Context(), areq)
		require.Error(t, err)

		require.NotNil(t, gotReq)
		assert.Equal(t, nethttp.MethodGet, gotReq.Method)
		assert.Equal(t, "http://test", gotReq.URL.String())
		for k, want := range expectedHeaders {
			assert.Equal(t, want, gotReq.Header.Get(k), "header %q", k)
		}
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", HTTPTimeout: time.Second}
		waf, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)
		response := &nethttp.Response{StatusCode: 500, Status: "500 error", Body: io.NopCloser(strings.NewReader(""))}
		expectedHeaders := map[string]string{
			"User-Agent":             "UA",
			"X-Crowdsec-Appsec-Ip":   "192.168.1.1",
			"X-Crowdsec-Appsec-Uri":  "/test",
			"X-Crowdsec-Appsec-Host": "localhost",
			"X-Crowdsec-Appsec-Verb": "GET",
		}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "UA"}, RealIP: "192.168.1.1", URL: url.URL{Scheme: "http", Host: "localhost", Path: "/test"}}
		_, err = waf.Inspect(t.Context(), areq)
		require.Error(t, err)

		require.NotNil(t, gotReq)
		assert.Equal(t, nethttp.MethodGet, gotReq.Method)
		assert.Equal(t, "http://test", gotReq.URL.String())
		for k, want := range expectedHeaders {
			assert.Equal(t, want, gotReq.Header.Get(k), "header %q", k)
		}
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", ApiKey: "key", HTTPTimeout: time.Second}
		waf, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)
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
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		result, err := waf.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, "ban", result.Action)
		assert.Equal(t, 403, result.HTTPStatus)

		require.NotNil(t, gotReq)
		assert.Equal(t, nethttp.MethodGet, gotReq.Method)
		assert.Equal(t, "http://test", gotReq.URL.String())
		for k, want := range expectedHeaders {
			assert.Equal(t, want, gotReq.Header.Get(k), "header %q", k)
		}
	})
	t.Run("with body", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", ApiKey: "key", HTTPTimeout: time.Second}
		waf, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)
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
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "POST", Headers: map[string]string{"Content-Type": "application/json", "user-agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}, Body: []byte("test")}
		result, err := waf.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, "captcha", result.Action)

		require.NotNil(t, gotReq)
		assert.Equal(t, nethttp.MethodPost, gotReq.Method)
		assert.Equal(t, "http://test", gotReq.URL.String())
		for k, want := range expectedHeaders {
			assert.Equal(t, want, gotReq.Header.Get(k), "header %q", k)
		}
	})

	t.Run("hung appsec returns an error once the timeout elapses", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", HTTPTimeout: 50 * time.Millisecond}
		waf, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		mockHTTP.EXPECT().Do(gomock.Any()).DoAndReturn(func(r *nethttp.Request) (*nethttp.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		_, err = waf.Inspect(t.Context(), areq)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("challenge action with body, cookies, and headers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{AppSecURL: "http://test", ApiKey: "key", HTTPTimeout: time.Second}
		waf, err := NewWAF(cfg, nethttp.DefaultClient)
		require.NoError(t, err)
		waf.http = mockHTTP
		respBody := `{"action":"challenge","http_status":401,"user_body_content":"<html>challenge</html>","user_cookies":["cs_challenge=abc123; Path=/; HttpOnly"],"user_headers":{"Content-Type":["text/html"],"Content-Security-Policy":["default-src 'self'"]}}`
		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(respBody))}
		mockHTTP.EXPECT().Do(gomock.Any()).Return(response, nil).Times(1)
		areq := AppSecRequest{Method: "GET", Headers: map[string]string{"user-agent": "test-agent"}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		result, err := waf.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, "challenge", result.Action)
		assert.Equal(t, 401, result.HTTPStatus)
		assert.Equal(t, "<html>challenge</html>", result.UserBodyContent)
		require.Len(t, result.UserCookies, 1, "expected one cookie in response")
		assert.Equal(t, "cs_challenge=abc123; Path=/; HttpOnly", result.UserCookies[0])
		require.Contains(t, result.UserHeaders, "Content-Type")
		assert.Equal(t, []string{"text/html"}, result.UserHeaders["Content-Type"])
		require.Contains(t, result.UserHeaders, "Content-Security-Policy")
		assert.Equal(t, []string{"default-src 'self'"}, result.UserHeaders["Content-Security-Policy"])
	})

	t.Run("routes to the matching host's target", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://test",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes:      []config.WAFRoute{{Hosts: []string{"api.example.com"}, Path: "/api-waf"}},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "api.example.com", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://test/api-waf", gotReq.URL.String())
	})

	t.Run("multiple routes: exact host match wins over wildcard and catch-all", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://test",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes: []config.WAFRoute{
				{Hosts: []string{"api.example.com"}, Path: "/api-waf"},
				{Hosts: []string{"*.example.com"}, Path: "/browser-waf"},
				{Hosts: []string{"*"}, Path: "/default-waf"},
			},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "api.example.com", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://test/api-waf", gotReq.URL.String())
	})

	t.Run("multiple routes: wildcard subdomain match wins over catch-all", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://test",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes: []config.WAFRoute{
				{Hosts: []string{"api.example.com"}, Path: "/api-waf"},
				{Hosts: []string{"*.example.com"}, Path: "/browser-waf"},
				{Hosts: []string{"*"}, Path: "/default-waf"},
			},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "other.example.com", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://test/browser-waf", gotReq.URL.String())
	})

	t.Run("multiple routes: catch-all matches an unrelated host", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://test",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes: []config.WAFRoute{
				{Hosts: []string{"api.example.com"}, Path: "/api-waf"},
				{Hosts: []string{"*.example.com"}, Path: "/browser-waf"},
				{Hosts: []string{"*"}, Path: "/default-waf"},
			},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		response := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response, nil).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "unrelated.test", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://test/default-waf", gotReq.URL.String())
	})

	t.Run("unmatched host is allowed without dispatching to any route", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://test",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes:      []config.WAFRoute{{Hosts: []string{"api.example.com"}, Path: "/api-waf"}},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		mockHTTP.EXPECT().Do(gomock.Any()).Times(0)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "unmatched.example.com", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "allow"}, result)
	})

	t.Run("route with a port dispatches to that port, leaving unrouted requests on the default port", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		cfg := config.WAF{
			AppSecURL:   "http://appsec",
			ApiKey:      "key",
			HTTPTimeout: time.Second,
			Routes: []config.WAFRoute{
				{Hosts: []string{"api.example.com"}, Path: "/api-waf", Port: 7423},
				{Hosts: []string{"browser.example.com"}, Path: "/browser-waf"},
			},
		}
		routedWAF, err := NewWAF(cfg, mockHTTP)
		require.NoError(t, err)

		response1 := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		var gotReq *nethttp.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response1, nil).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "api.example.com", Path: "/foo"}}
		result, err := routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://appsec:7423/api-waf", gotReq.URL.String())

		gotReq = nil
		response2 := &nethttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"ban"}`))}
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *nethttp.Request) { gotReq = r }).Return(response2, nil).Times(1)
		areq = AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "browser.example.com", Path: "/foo"}}
		result, err = routedWAF.Inspect(t.Context(), areq)
		require.NoError(t, err)
		assert.Equal(t, WAFResponse{Action: "ban"}, result)
		require.NotNil(t, gotReq)
		assert.Equal(t, "http://appsec/browser-waf", gotReq.URL.String())
	})
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "lowercased unchanged", host: "Example.com", want: "example.com"},
		{name: "port stripped", host: "Example.com:8080", want: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeHost(tt.host))
		})
	}
}

func TestHostMatches(t *testing.T) {
	tests := []struct {
		name     string
		patterns [][]string
		host     []string
		want     bool
	}{
		{name: "exact match", patterns: [][]string{{"api", "example", "com"}}, host: []string{"api", "example", "com"}, want: true},
		{name: "wildcard subdomain match", patterns: [][]string{{"*", "example", "com"}}, host: []string{"api", "example", "com"}, want: true},
		{name: "catch-all match", patterns: [][]string{{"*"}}, host: []string{"anything", "example", "com"}, want: true},
		{name: "no pattern matches", patterns: [][]string{{"api", "example", "com"}}, host: []string{"other", "example", "com"}, want: false},
		{name: "wildcard subdomain does not match apex", patterns: [][]string{{"*", "example", "com"}}, host: []string{"example", "com"}, want: false},
		{name: "wildcard subdomain does not match nested subdomain", patterns: [][]string{{"*", "example", "com"}}, host: []string{"a", "b", "example", "com"}, want: false},
		{name: "multi-level wildcard matches exact depth", patterns: [][]string{{"*", "test", "example", "com"}}, host: []string{"foo", "test", "example", "com"}, want: true},
		{name: "multi-level wildcard does not match deeper depth", patterns: [][]string{{"*", "test", "example", "com"}}, host: []string{"foo", "bar", "test", "example", "com"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hostMatches(tt.patterns, tt.host))
		})
	}
}
