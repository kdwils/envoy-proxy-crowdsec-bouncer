package webhook

import "time"

type EventType string

const (
	EventRequestBlocked  EventType = "request_blocked"
	EventCaptchaRequired EventType = "captcha_required"
	EventCaptchaVerified EventType = "captcha_verified"
	EventRequestAllowed  EventType = "request_allowed"
)

type Event struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	Request   *Request  `json:"request,omitempty"`
}

type Request struct {
	Method    string `json:"method,omitempty"`
	URL       string `json:"url,omitempty"`
	Host      string `json:"host,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
	Path      string `json:"path,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}
