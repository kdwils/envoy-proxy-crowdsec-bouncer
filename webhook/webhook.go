package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/types"
)

type Service struct {
	subsByEvent map[EventType][]string
	signingKey  string
	http        types.HTTPClient
	timeout     time.Duration
	events      chan Event
	now         func() time.Time
}

func New(subscriptions []config.Subscription, signingKey string, timeout time.Duration, bufferSize int, client types.HTTPClient) *Service {
	t := timeout
	if t == 0 {
		t = 5 * time.Second
	}
	b := bufferSize
	if b == 0 {
		b = 100
	}
	return &Service{
		subsByEvent: buildSubsByEvent(subscriptions),
		signingKey:  signingKey,
		http:        client,
		timeout:     t,
		events:      make(chan Event, b),
		now:         time.Now,
	}
}

func buildSubsByEvent(subscriptions []config.Subscription) map[EventType][]string {
	byEvent := make(map[EventType][]string)
	for _, sub := range subscriptions {
		for _, e := range sub.Events {
			eventType, ok := parseEventType(e)
			if !ok {
				continue
			}
			if !slices.Contains(byEvent[eventType], sub.URL) {
				byEvent[eventType] = append(byEvent[eventType], sub.URL)
			}
		}
	}
	return byEvent
}

func parseEventType(s string) (EventType, bool) {
	switch EventType(s) {
	case EventRequestBlocked, EventCaptchaRequired, EventCaptchaVerified, EventRequestAllowed:
		return EventType(s), true
	default:
		return "", false
	}
}

func (s *Service) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.events:
			s.dispatch(ctx, event)
		}
	}
}

func (s *Service) NotifyCheckedRequest(ctx context.Context, result bouncer.CheckedRequest) {
	eventType, ok := eventTypeForAction(result.Action)
	if !ok {
		return
	}
	if !s.subscribedTo(eventType) {
		return
	}
	s.enqueue(ctx, s.buildCheckedRequestEvent(eventType, result))
}

func (s *Service) NotifyCaptchaVerified(ctx context.Context, ip string) {
	if !s.subscribedTo(EventCaptchaVerified) {
		return
	}
	s.enqueue(ctx, Event{
		Type:      EventCaptchaVerified,
		Timestamp: s.now().UTC(),
		IP:        ip,
		Action:    "allow",
		Reason:    "captcha verified",
	})
}

func (s *Service) subscribedTo(t EventType) bool {
	return len(s.subsByEvent[t]) > 0
}

func (s *Service) enqueue(ctx context.Context, event Event) {
	select {
	case s.events <- event:
	default:
		logger.FromContext(ctx).Debug("webhook event dropped, channel full")
	}
}

func eventTypeForAction(action string) (EventType, bool) {
	switch action {
	case "allow":
		return EventRequestAllowed, true
	case "ban", "deny":
		return EventRequestBlocked, true
	case "captcha":
		return EventCaptchaRequired, true
	default:
		return "", false
	}
}

func (s *Service) buildCheckedRequestEvent(eventType EventType, result bouncer.CheckedRequest) Event {
	event := Event{
		Type:      eventType,
		Timestamp: s.now().UTC(),
		IP:        result.IP,
		Action:    result.Action,
		Reason:    result.Reason,
	}

	if result.ParsedRequest == nil {
		return event
	}

	event.Request = &Request{
		Method:    result.ParsedRequest.Method,
		URL:       result.ParsedRequest.URL.String(),
		Host:      result.ParsedRequest.URL.Host,
		Scheme:    result.ParsedRequest.URL.Scheme,
		Path:      result.ParsedRequest.URL.Path,
		UserAgent: result.ParsedRequest.UserAgent,
	}

	return event
}

func (s *Service) dispatch(ctx context.Context, event Event) {
	urls := s.subsByEvent[event.Type]

	body, err := json.Marshal(event)
	if err != nil {
		logger.FromContext(ctx).Error("webhook marshal error", "error", err)
		return
	}

	for _, url := range urls {
		s.send(ctx, url, body)
	}
}

func (s *Service) send(ctx context.Context, endpoint string, body []byte) {
	reqCtx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		logger.FromContext(ctx).Error("webhook request creation error", "endpoint", endpoint, "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.signingKey != "" {
		req.Header.Set("X-Signature-SHA256", computeHMAC(body, s.signingKey))
	}

	resp, err := s.http.Do(req)
	if err != nil {
		logger.FromContext(ctx).Error("webhook delivery error", "endpoint", endpoint, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.FromContext(ctx).Warn("webhook non-success response", "endpoint", endpoint, "status", resp.StatusCode)
	}
}

func computeHMAC(body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

var noopNotifier = &NoopNotifier{}

type NoopNotifier struct{}

func NewNoopNotifier() *NoopNotifier {
	return noopNotifier
}

func (n *NoopNotifier) NotifyCheckedRequest(_ context.Context, _ bouncer.CheckedRequest) {}

func (n *NoopNotifier) NotifyCaptchaVerified(_ context.Context, _ string) {}
