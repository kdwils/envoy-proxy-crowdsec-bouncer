package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Notify(t *testing.T) {
	t.Run("sends event to subscribed endpoint", func(t *testing.T) {
		received := make(chan []byte, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			received <- buf[:n]
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		svc := New(
			[]Subscription{{URL: srv.URL, Events: []EventType{EventRequestBlocked}}},
			"",
			time.Second,
			0,
			http.DefaultClient,
		)

		go svc.Start(t.Context())

		want := Event{
			Type:      EventRequestBlocked,
			Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			IP:        "1.2.3.4",
			Action:    "ban",
			Reason:    "crowdsecurity/ssh-bf",
		}

		svc.Notify(t.Context(), want)

		select {
		case body := <-received:
			var got Event
			err := json.Unmarshal(body, &got)
			require.NoError(t, err, "expected valid JSON payload")
			assert.Equal(t, want, got, "expected event payload to match")
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for webhook delivery")
		}
	})

	t.Run("does not send to endpoint not subscribed to event type", func(t *testing.T) {
		called := make(chan struct{}, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called <- struct{}{}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		svc := New(
			[]Subscription{{URL: srv.URL, Events: []EventType{EventCaptchaRequired}}},
			"",
			time.Second,
			0,
			http.DefaultClient,
		)

		go svc.Start(t.Context())

		svc.Notify(t.Context(), Event{Type: EventRequestBlocked, IP: "1.2.3.4"})

		select {
		case <-called:
			t.Fatal("expected no webhook delivery for unsubscribed event type")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("sends HMAC signature when signing key configured", func(t *testing.T) {
		received := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r.Header.Get("X-Signature-SHA256")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		svc := New(
			[]Subscription{{URL: srv.URL, Events: []EventType{EventRequestAllowed}}},
			"secret",
			time.Second,
			0,
			http.DefaultClient,
		)

		go svc.Start(t.Context())

		svc.Notify(t.Context(), Event{Type: EventRequestAllowed, IP: "1.2.3.4"})

		select {
		case sig := <-received:
			assert.NotEmpty(t, sig, "expected HMAC signature header")
			assert.Len(t, sig, 64, "expected 64-char hex SHA256 HMAC")
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for webhook delivery")
		}
	})

	t.Run("no HMAC header when no signing key", func(t *testing.T) {
		received := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			received <- r.Header.Get("X-Signature-SHA256")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		svc := New(
			[]Subscription{{URL: srv.URL, Events: []EventType{EventRequestAllowed}}},
			"",
			time.Second,
			0,
			http.DefaultClient,
		)

		go svc.Start(t.Context())

		svc.Notify(t.Context(), Event{Type: EventRequestAllowed, IP: "1.2.3.4"})

		select {
		case sig := <-received:
			assert.Empty(t, sig, "expected no HMAC signature header")
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for webhook delivery")
		}
	})

	t.Run("no-op when no subscriptions", func(t *testing.T) {
		svc := New(nil, "", time.Second, 0, http.DefaultClient)
		go svc.Start(t.Context())
		svc.Notify(t.Context(), Event{Type: EventRequestBlocked, IP: "1.2.3.4"})
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

func TestNoopNotifier(t *testing.T) {
	t.Run("notify does nothing", func(t *testing.T) {
		n := NewNoopNotifier()
		n.Notify(context.Background(), Event{Type: EventRequestBlocked})
	})
}
