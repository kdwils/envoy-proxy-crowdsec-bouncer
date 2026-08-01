package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
)

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_http_client.go -package=mocks github.com/kdwils/envoy-proxy-bouncer/webhook HTTPClient
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Service struct {
	subsByEvent map[EventType][]string
	signingKey  string
	http        HTTPClient
	timeout     time.Duration
	events      chan Event
	now         func() time.Time
}

func New(subscriptions []config.Subscription, signingKey string, timeout time.Duration, bufferSize int, client HTTPClient) *Service {
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

type eventURL struct {
	event EventType
	url   string
}

func buildSubsByEvent(subscriptions []config.Subscription) map[EventType][]string {
	byEvent := make(map[EventType][]string)
	seen := make(map[eventURL]struct{}, len(subscriptions))
	for _, sub := range subscriptions {
		for _, e := range sub.Events {
			eventType, ok := parseEventType(e)
			if !ok {
				continue
			}
			key := eventURL{event: eventType, url: sub.URL}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			byEvent[eventType] = append(byEvent[eventType], sub.URL)
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
	eventType, err := eventTypeForAction(result.Action)
	if err != nil {
		logger.FromContext(ctx).Error("webhook event type not derivable", "action", result.Action, "error", err)
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
	log := logger.FromContext(ctx)
	select {
	case s.events <- event:
	default:
		log.Warn("webhook event dropped, channel full")
	}
}

func eventTypeForAction(action string) (EventType, error) {
	switch action {
	case "allow":
		return EventRequestAllowed, nil
	case "ban", "deny":
		return EventRequestBlocked, nil
	case "captcha":
		return EventCaptchaRequired, nil
	default:
		return "", fmt.Errorf("unsupported action %q", action)
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
	log := logger.FromContext(ctx)
	urls := s.subsByEvent[event.Type]

	body, err := json.Marshal(event)
	if err != nil {
		log.Error("webhook marshal error", "error", err)
		return
	}

	for _, url := range urls {
		s.send(ctx, url, body)
	}
}

func (s *Service) send(ctx context.Context, endpoint string, body []byte) {
	log := logger.FromContext(ctx)
	reqCtx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Error("webhook request creation error", "endpoint", endpoint, "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if s.signingKey != "" {
		req.Header.Set("X-Signature-SHA256", computeHMAC(body, s.signingKey))
	}

	resp, err := s.http.Do(req)
	if err != nil {
		log.Error("webhook delivery error", "endpoint", endpoint, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Warn("webhook non-success response", "endpoint", endpoint, "status", resp.StatusCode)
	}
}

func computeHMAC(body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

type NoopNotifier struct{}

func NewNoopNotifier() *NoopNotifier {
	return &NoopNotifier{}
}

func (n *NoopNotifier) NotifyCheckedRequest(_ context.Context, _ bouncer.CheckedRequest) {}

func (n *NoopNotifier) NotifyCaptchaVerified(_ context.Context, _ string) {}
