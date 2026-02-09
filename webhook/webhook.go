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

	"github.com/kdwils/envoy-proxy-bouncer/logger"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Subscription struct {
	URL    string      `yaml:"url" json:"url"`
	Events []EventType `yaml:"events" json:"events"`
}

type Service struct {
	subscriptions []Subscription
	signingKey    string
	http          HTTPClient
	timeout       time.Duration
	events        chan Event
}

func New(subscriptions []Subscription, signingKey string, timeout time.Duration, bufferSize int, client HTTPClient) *Service {
	t := timeout
	if t == 0 {
		t = 5 * time.Second
	}
	b := bufferSize
	if b == 0 {
		b = 100
	}
	return &Service{
		subscriptions: subscriptions,
		signingKey:    signingKey,
		http:          client,
		timeout:       t,
		events:        make(chan Event, b),
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

func (s *Service) Notify(ctx context.Context, event Event) {
	log := logger.FromContext(ctx)
	select {
	case s.events <- event:
	default:
		log.Warn("webhook event dropped, channel full")
	}
}

func (s *Service) dispatch(ctx context.Context, event Event) {
	log := logger.FromContext(ctx)
	body, err := json.Marshal(event)
	if err != nil {
		log.Error("webhook marshal error", "error", err)
		return
	}
	for _, sub := range s.subscriptions {
		if !sub.subscribedTo(event.Type) {
			continue
		}
		s.send(ctx, sub.URL, body)
	}
}

func (sub Subscription) subscribedTo(t EventType) bool {
	return slices.Contains(sub.Events, t)
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

func (n *NoopNotifier) Notify(_ context.Context, _ Event) {}
