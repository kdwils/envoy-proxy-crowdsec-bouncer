package bouncer

import (
	"errors"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/kdwils/envoy-gateway-bouncer/bouncer/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEnvoyBouncer_Bounce(t *testing.T) {

	t.Run("empty ip", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		banned, err := b.Bounce("", nil)
		assert.Error(t, err)
		assert.Equal(t, "no ip found", err.Error())
		assert.False(t, banned)
	})

	t.Run("header too big", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		headers := map[string]string{
			"x-forwarded-for": strings.Repeat("a", maxHeaderLength+1),
		}
		banned, err := b.Bounce("192.168.1.1", headers)
		assert.Error(t, err)
		assert.Equal(t, "header too big", err.Error())
		assert.False(t, banned)
	})

	t.Run("too many ips in chain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		ips := make([]string, maxIPs+1)
		for i := range ips {
			ips[i] = "192.168.1.1"
		}
		headers := map[string]string{
			"x-forwarded-for": strings.Join(ips, ","),
		}
		banned, err := b.Bounce("192.168.1.1", headers)
		assert.Error(t, err)
		assert.Equal(t, "too many ips in chain", err.Error())
		assert.False(t, banned)
	})

	t.Run("invalid ip", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		banned, err := b.Bounce("not-an-ip", nil)
		assert.Error(t, err)
		assert.Equal(t, "invalid ip address", err.Error())
		assert.False(t, banned)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, errors.New("bouncer error"))
		banned, err := b.Bounce("192.168.1.1", nil)
		assert.Error(t, err)
		assert.Equal(t, "bouncer error", err.Error())
		assert.False(t, banned)
	})

	t.Run("no decisions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, nil)
		banned, err := b.Bounce("192.168.1.1", nil)
		assert.NoError(t, err)
		assert.False(t, banned)
	})

	t.Run("ip banned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		ip := "192.168.1.1"
		decisionType := "ban"
		decisions := &models.GetDecisionsResponse{
			{
				Value: &ip,
				Type:  &decisionType,
			},
		}
		mockBouncer.EXPECT().Get(ip).Return(decisions, nil)
		banned, err := b.Bounce(ip, nil)
		assert.NoError(t, err)
		assert.True(t, banned)
	})

	t.Run("ip not banned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{bouncer: mockBouncer}
		ip := "192.168.1.1"
		decisionType := "allow"
		decisions := &models.GetDecisionsResponse{
			{
				Value: &ip,
				Type:  &decisionType,
			},
		}
		mockBouncer.EXPECT().Get(ip).Return(decisions, nil)
		banned, err := b.Bounce(ip, nil)
		assert.NoError(t, err)
		assert.False(t, banned)
	})

	t.Run("trusted proxy chain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockLiveBouncerClient(ctrl)
		b := &EnvoyBouncer{
			bouncer:        mockBouncer,
			trustedProxies: []string{"10.0.0.1"},
		}
		headers := map[string]string{
			"x-forwarded-for": "192.168.1.1,10.0.0.1",
		}
		mockBouncer.EXPECT().Get("192.168.1.1").Return(nil, nil)
		banned, err := b.Bounce("1.1.1.1", headers)
		assert.NoError(t, err)
		assert.False(t, banned)
	})
}
