package cache

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func ptr[T any](v T) *T {
	return &v
}

func TestDecisionCache(t *testing.T) {
	c := New[models.Decision]()
	if c.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", c.Size())
	}

	ip := "192.168.1.1"
	decision := models.Decision{
		ID:       1,
		Origin:   ptr("test"),
		Type:     ptr("ban"),
		Value:    &ip,
		Duration: ptr(time.Hour.String()),
		Scenario: ptr("test"),
	}
	c.Set(ip, decision)
	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}
	got, ok := c.Get(ip)
	if !ok {
		t.Errorf("expected to find entry for %s", ip)
	}
	if *got.Value != ip {
		t.Errorf("expected ip %s, got %s", ip, *got.Value)
	}
	c.Delete(ip)
	if c.Size() != 0 {
		t.Errorf("expected empty cache after delete, got size %d", c.Size())
	}

	_, ok = c.Get(ip)
	if ok {
		t.Errorf("expected no entry for %s after delete", ip)
	}
}

func TestCaptchaCache(t *testing.T) {
	c := New[time.Time]()
	if c.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", c.Size())
	}

	ip := "192.168.1.1"
	expiry := time.Now().Add(time.Hour)
	c.Set(ip, expiry)
	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}

	got, ok := c.Get(ip)
	if !ok {
		t.Errorf("expected to find entry for %s", ip)
	}
	if !got.Equal(expiry) {
		t.Errorf("expected expiry %v, got %v", expiry, got)
	}

	c.Delete(ip)
	if c.Size() != 0 {
		t.Errorf("expected empty cache after delete, got size %d", c.Size())
	}

	_, ok = c.Get(ip)
	if ok {
		t.Errorf("expected no entry for %s after delete", ip)
	}
}
