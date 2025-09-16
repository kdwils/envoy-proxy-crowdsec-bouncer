package server

import (
	"context"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/remediation"
	"github.com/kdwils/envoy-proxy-bouncer/server/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestServer_Check(t *testing.T) {
	log := logger.FromContext(context.Background())
	t.Run("bouncer not initialized", func(t *testing.T) {
		s := NewServer(config.Config{}, nil, nil, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "error",
			Reason:     "test error",
			HTTPStatus: 500,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "test error")
	})

	t.Run("request blocked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "deny",
			Reason:     "blocked",
			HTTPStatus: 403,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
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

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
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
		assert.Nil(t, resp.GetDeniedResponse())
	})
}

func TestServer_Check_WithRemediator(t *testing.T) {
	t.Run("remediator returns error", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)

		defer ctrl.Finish()
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "error",
			Reason:     "remediator error",
			HTTPStatus: 500,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "remediator error")
	})

	t.Run("remediator returns deny", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "deny",
			Reason:     "blocked",
			HTTPStatus: 403,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "blocked")
	})

	t.Run("remediator returns allow", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.Status.Code)
		assert.Nil(t, resp.GetDeniedResponse())
	})
}
