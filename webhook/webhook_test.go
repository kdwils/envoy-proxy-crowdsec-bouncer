package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/webhook/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newService(t *testing.T, subs []config.Subscription, signingKey string) (*Service, *mocks.MockHTTPClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mockHTTP := mocks.NewMockHTTPClient(ctrl)
	return New(subs, signingKey, time.Second, 0, mockHTTP), mockHTTP
}

func assertEvent(t *testing.T, svc *Service, want Event) {
	t.Helper()
	select {
	case got := <-svc.events:
		assert.Equal(t, want, got, "expected event payload to match")
	default:
		t.Fatal("expected event to be enqueued")
	}
}

func assertNoEvent(t *testing.T, svc *Service) {
	t.Helper()
	select {
	case got := <-svc.events:
		t.Fatalf("expected no event enqueued, got %+v", got)
	default:
	}
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}
}

func TestService_NotifyCheckedRequest(t *testing.T) {
	t.Run("enqueues request_blocked event for ban action", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"request_blocked"}}}, "")
		svc.now = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }

		svc.NotifyCheckedRequest(t.Context(), bouncer.CheckedRequest{
			IP:     "1.2.3.4",
			Action: "ban",
			Reason: "crowdsecurity/ssh-bf",
		})

		assertEvent(t, svc, Event{
			Type:      EventRequestBlocked,
			Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			IP:        "1.2.3.4",
			Action:    "ban",
			Reason:    "crowdsecurity/ssh-bf",
		})
	})

	t.Run("enqueues request_allowed event for allow action", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"request_allowed"}}}, "")
		svc.now = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }

		svc.NotifyCheckedRequest(t.Context(), bouncer.CheckedRequest{
			IP:     "1.2.3.4",
			Action: "allow",
		})

		assertEvent(t, svc, Event{
			Type:      EventRequestAllowed,
			Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			IP:        "1.2.3.4",
			Action:    "allow",
		})
	})

	t.Run("does not enqueue when not subscribed to event type", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"captcha_required"}}}, "")

		svc.NotifyCheckedRequest(t.Context(), bouncer.CheckedRequest{
			IP:     "1.2.3.4",
			Action: "ban",
		})

		assertNoEvent(t, svc)
	})

	t.Run("does not enqueue event when action is error", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"request_blocked"}}}, "")

		svc.NotifyCheckedRequest(t.Context(), bouncer.CheckedRequest{
			IP:     "1.2.3.4",
			Action: "error",
			Reason: "remediator error",
		})

		assertNoEvent(t, svc)
	})

	t.Run("no-op when no subscriptions", func(t *testing.T) {
		svc, _ := newService(t, nil, "")

		svc.NotifyCheckedRequest(t.Context(), bouncer.CheckedRequest{
			IP:     "1.2.3.4",
			Action: "ban",
		})

		assertNoEvent(t, svc)
	})
}

func TestService_NotifyCaptchaVerified(t *testing.T) {
	t.Run("enqueues captcha verified event", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"captcha_verified"}}}, "")
		svc.now = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }

		svc.NotifyCaptchaVerified(t.Context(), "1.2.3.4")

		assertEvent(t, svc, Event{
			Type:      EventCaptchaVerified,
			Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			IP:        "1.2.3.4",
			Action:    "allow",
			Reason:    "captcha verified",
		})
	})

	t.Run("does not enqueue when not subscribed", func(t *testing.T) {
		svc, _ := newService(t, []config.Subscription{{URL: "http://example.com", Events: []string{"request_blocked"}}}, "")

		svc.NotifyCaptchaVerified(t.Context(), "1.2.3.4")

		assertNoEvent(t, svc)
	})
}

func TestService_Dispatch(t *testing.T) {
	t.Run("posts event to subscribed endpoint", func(t *testing.T) {
		svc, mockHTTP := newService(t, []config.Subscription{{URL: "http://example.com/webhook", Events: []string{"request_blocked"}}}, "")

		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return okResponse(), nil
		})

		want := Event{
			Type:      EventRequestBlocked,
			Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			IP:        "1.2.3.4",
			Action:    "ban",
			Reason:    "crowdsecurity/ssh-bf",
		}

		svc.dispatch(t.Context(), want)

		require.NotNil(t, gotReq, "expected webhook request")
		assert.Equal(t, "http://example.com/webhook", gotReq.URL.String())
		assert.Equal(t, "application/json", gotReq.Header.Get("Content-Type"))

		body, err := io.ReadAll(gotReq.Body)
		require.NoError(t, err, "expected readable request body")

		var got Event
		require.NoError(t, json.Unmarshal(body, &got), "expected valid JSON payload")
		assert.Equal(t, want, got, "expected event payload to match")
	})

	t.Run("sets HMAC signature when signing key configured", func(t *testing.T) {
		svc, mockHTTP := newService(t, []config.Subscription{{URL: "http://example.com/webhook", Events: []string{"request_allowed"}}}, "secret")

		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return okResponse(), nil
		})

		svc.dispatch(t.Context(), Event{
			Type:   EventRequestAllowed,
			IP:     "1.2.3.4",
			Action: "allow",
		})

		require.NotNil(t, gotReq, "expected webhook request")
		sig := gotReq.Header.Get("X-Signature-SHA256")
		assert.NotEmpty(t, sig, "expected HMAC signature header")
		assert.Len(t, sig, 64, "expected 64-char hex SHA256 HMAC")
	})

	t.Run("no HMAC header when no signing key", func(t *testing.T) {
		svc, mockHTTP := newService(t, []config.Subscription{{URL: "http://example.com/webhook", Events: []string{"request_allowed"}}}, "")

		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return okResponse(), nil
		})

		svc.dispatch(t.Context(), Event{
			Type:   EventRequestAllowed,
			IP:     "1.2.3.4",
			Action: "allow",
		})

		require.NotNil(t, gotReq, "expected webhook request")
		assert.Empty(t, gotReq.Header.Get("X-Signature-SHA256"), "expected no HMAC signature header")
	})

	t.Run("skips endpoint not subscribed to event type", func(t *testing.T) {
		svc, mockHTTP := newService(t, []config.Subscription{{URL: "http://example.com/webhook", Events: []string{"captcha_required"}}}, "")
		mockHTTP.EXPECT().Do(gomock.Any()).Times(0)

		svc.dispatch(t.Context(), Event{
			Type:   EventRequestBlocked,
			IP:     "1.2.3.4",
			Action: "ban",
		})
	})
}

func TestComputeHMAC(t *testing.T) {
	t.Run("produces consistent output", func(t *testing.T) {
		body := []byte(`{"type":"request_blocked"}`)
		key := "test-secret"

		sig1 := computeHMAC(body, key)
		sig2 := computeHMAC(body, key)

		assert.Equal(t, sig1, sig2, "expected deterministic HMAC")
		assert.Len(t, sig1, 64, "expected 64-char hex SHA256")
	})

	t.Run("different keys produce different signatures", func(t *testing.T) {
		body := []byte(`{"type":"request_blocked"}`)

		sig1 := computeHMAC(body, "key1")
		sig2 := computeHMAC(body, "key2")

		assert.NotEqual(t, sig1, sig2, "expected different signatures for different keys")
	})
}
