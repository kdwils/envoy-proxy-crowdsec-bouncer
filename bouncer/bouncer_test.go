package bouncer

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/kdwils/envoy-gateway-bouncer/bouncer/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEnvoyBouncer_Bounce(t *testing.T) {
	t.Run("error getting decisions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, errors.New("error getting decisions"))

		bouncer := EnvoyBouncer{
			bouncer: mockBouncer,
		}

		req := &http.Request{
			RemoteAddr: "192.168.1.1:12345",
		}

		bounce, err := bouncer.Bounce(req)
		assert.Error(t, err)
		assert.False(t, bounce)
	})

	t.Run("no decisions found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		mockBouncer.EXPECT().Get("192.168.1.1").Return(&models.GetDecisionsResponse{}, nil)

		bouncer := EnvoyBouncer{
			bouncer: mockBouncer,
		}

		req := &http.Request{
			RemoteAddr: "192.168.1.1:12345",
		}

		bounce, err := bouncer.Bounce(req)
		assert.NoError(t, err)
		assert.False(t, bounce)
	})

	t.Run("decision found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		mockBouncer.EXPECT().Get("192.168.1.1").Return(&models.GetDecisionsResponse{
			{
				Value:    ptr("192.168.1.1"),
				Scope:    ptr("ip"),
				Duration: ptr("1h"),
				Type:     ptr("ban"),
			},
		}, nil)

		bouncer := EnvoyBouncer{
			bouncer: mockBouncer,
		}

		req := &http.Request{
			RemoteAddr: "192.168.1.1:12345",
		}

		bounce, err := bouncer.Bounce(req)
		assert.NoError(t, err)
		assert.True(t, bounce)
	})
}

func TestEnvoyBouncer_getRequestIP(t *testing.T) {
	t.Run("get ip from header", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{"X-Real-IP"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("X-Real-IP", "192.168.1.1")

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("get ip from x-forwarded-for header with trusted proxy", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers:        []string{"X-Forwarded-For"},
			trustedProxies: []string{"10.0.0.1"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("get ip from remote addr", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{},
		}

		req := &http.Request{
			RemoteAddr: "192.168.1.1:12345",
		}

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("get ip from remote addr without port", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{},
		}

		req := &http.Request{
			RemoteAddr: "192.168.1.1",
		}

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})
	t.Run("get ipv6 from remote addr", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{},
		}

		req := &http.Request{
			RemoteAddr: "[2001:db8::1]:12345",
		}

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "2001:db8::1", ip)
	})

	t.Run("invalid ip in header", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{"X-Real-IP"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("X-Real-IP", "not-an-ip")

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "", ip)
	})

	t.Run("header exceeds max length", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{"X-Forwarded-For"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}

		longIP := strings.Repeat("192.168.1.1,", maxHeaderLength)
		req.Header.Set("X-Forwarded-For", longIP)

		ip := bouncer.getRequestIP(req)
		assert.Equal(t, "", ip)
	})
}

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"valid IPv4", "192.168.1.1", true},
		{"valid IPv6", "2001:db8::1", true},
		{"invalid IP", "not an ip", false},
		{"empty string", "", false},
		{"IPv4 with port", "192.168.1.1:8080", false},
		{"IPv6 with port", "[2001:db8::1]:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIP(tt.ip)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEnvoyBouncer_getIPFromHeader(t *testing.T) {
	t.Run("trusted proxy chain", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			trustedProxies: []string{"10.0.0.1", "10.0.0.2"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.2, 10.0.0.1")

		ip := bouncer.getIPFromHeader(req, "X-Forwarded-For")
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("all trusted proxies", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			trustedProxies: []string{"10.0.0.1", "10.0.0.2"},
		}

		req := &http.Request{
			Header: make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.1")

		ip := bouncer.getIPFromHeader(req, "X-Forwarded-For")
		assert.Equal(t, "", ip)
	})

	t.Run("too many ips in chain", func(t *testing.T) {
		bouncer := EnvoyBouncer{}

		req := &http.Request{
			Header: make(http.Header),
		}
		ips := make([]string, maxIPs+1)
		for i := range ips {
			ips[i] = "192.168.1.1"
		}
		req.Header.Set("X-Forwarded-For", strings.Join(ips, ", "))

		ip := bouncer.getIPFromHeader(req, "X-Forwarded-For")
		assert.Equal(t, "", ip)
	})
}
