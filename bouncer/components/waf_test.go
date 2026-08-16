package components

import (
	errors "errors"
	io "io"
	nethttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewForwardRequest(t *testing.T) {
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
		r := newForwardRequest(t.Context(), apiURL, areq, "key")

		assert.Equal(t, nethttp.MethodGet, r.Method)
		assert.Equal(t, apiURL, r.URL)
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
		_, err := NewWAF(":badurl", "", time.Second, nethttp.DefaultClient)
		assert.Error(t, err)
	})

	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
<<<<<<< HEAD
		waf, err := NewWAF("http://test", "", nethttp.DefaultClient)
=======
		waf, err := NewWAF("http://test", "", time.Second, nethttp.DefaultClient)
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7
		require.NoError(t, err)
		waf.http = mockHTTP
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
<<<<<<< HEAD
		waf, err := NewWAF("http://test", "", nethttp.DefaultClient)
=======
		waf, err := NewWAF("http://test", "", time.Second, nethttp.DefaultClient)
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7
		require.NoError(t, err)
		waf.http = mockHTTP
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
<<<<<<< HEAD
		waf, err := NewWAF("http://test", "key", nethttp.DefaultClient)
=======
		waf, err := NewWAF("http://test", "key", time.Second, nethttp.DefaultClient)
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7
		require.NoError(t, err)
		waf.http = mockHTTP
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
<<<<<<< HEAD

		require.NotNil(t, gotReq)
		assert.Equal(t, nethttp.MethodGet, gotReq.Method)
		assert.Equal(t, "http://test", gotReq.URL.String())
		for k, want := range expectedHeaders {
			assert.Equal(t, want, gotReq.Header.Get(k), "header %q", k)
		}
	})
=======
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7

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
<<<<<<< HEAD
		waf, err := NewWAF("http://test", "key", nethttp.DefaultClient)
=======
		waf, err := NewWAF("http://test", "key", time.Second, nethttp.DefaultClient)
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7
		require.NoError(t, err)
		waf.http = mockHTTP
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
<<<<<<< HEAD
=======
	})

	t.Run("hung appsec returns an error once the timeout elapses", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		waf, err := NewWAF("http://test", "", 50*time.Millisecond, nethttp.DefaultClient)
		require.NoError(t, err)
		waf.http = mockHTTP

		mockHTTP.EXPECT().Do(gomock.Any()).DoAndReturn(func(r *nethttp.Request) (*nethttp.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}).Times(1)

		areq := AppSecRequest{Method: "GET", Headers: map[string]string{}, RealIP: "1.2.3.4", URL: url.URL{Scheme: "http", Host: "example.com", Path: "/foo"}}
		_, err = waf.Inspect(context.Background(), areq)
		require.ErrorIs(t, err, context.DeadlineExceeded)
>>>>>>> b7308db40165c9d6a805fc5c43d1960b380992b7
	})

}
