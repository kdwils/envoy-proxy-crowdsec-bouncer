package bouncer

import (
	"errors"
	"net/http"
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

	t.Run("get ip from x-forwarded-for header", func(t *testing.T) {
		bouncer := EnvoyBouncer{
			headers: []string{"X-Forwarded-For"},
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
}
