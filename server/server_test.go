package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdwils/envoy-gateway-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-gateway-bouncer/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestServer_Check(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		s := NewServer(config.Config{}, nil)
		req := httptest.NewRequest(http.MethodPost, "/check", nil)
		w := httptest.NewRecorder()

		s.Check()(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("bouncer not initialized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		s := NewServer(config.Config{}, nil)
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		w := httptest.NewRecorder()

		s.Check()(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().
			Bounce(gomock.Any()).
			Return(false, assert.AnError)

		s := NewServer(config.Config{}, mockBouncer)
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		w := httptest.NewRecorder()

		s.Check()(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("request blocked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().
			Bounce(gomock.Any()).
			Return(true, nil)

		s := NewServer(config.Config{}, mockBouncer)
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		w := httptest.NewRecorder()

		s.Check()(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("request allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Bounce(gomock.Any()).Return(false, nil)

		s := NewServer(config.Config{}, mockBouncer)
		req := httptest.NewRequest(http.MethodGet, "/check", nil)
		w := httptest.NewRecorder()

		s.Check()(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
