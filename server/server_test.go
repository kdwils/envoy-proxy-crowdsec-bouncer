package server

import (
	"context"
	"fmt"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/kdwils/envoy-gateway-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-gateway-bouncer/config"
	"github.com/kdwils/envoy-gateway-bouncer/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestServer_Check(t *testing.T) {
	log := logger.FromContext(context.Background())
	t.Run("bouncer not initialized", func(t *testing.T) {
		s := NewServer(config.Config{}, nil, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().
			Bounce(gomock.Any(), "", gomock.Any()).
			Return(false, fmt.Errorf("test error"))

		s := NewServer(config.Config{}, mockBouncer, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
	})

	t.Run("request blocked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().
			Bounce(gomock.Any(), "192.0.2.1", gomock.Any()).
			Return(true, nil)

		s := NewServer(config.Config{}, mockBouncer, log)
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Address: "192.0.2.1",
							},
						},
					},
				},
			},
		}

		resp, err := s.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
	})

	t.Run("request allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().
			Bounce(gomock.Any(), "192.0.2.1", gomock.Any()).
			Return(false, nil)

		s := NewServer(config.Config{}, mockBouncer, log)
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Address: "192.0.2.1",
							},
						},
					},
				},
			},
		}

		resp, err := s.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.Status.Code) // OK
	})
}
