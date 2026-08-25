package captcha

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	mocks "github.com/kdwils/envoy-proxy-bouncer/types/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewRecaptchaProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockHTTP := mocks.NewMockHTTPClient(ctrl)

	provider, err := NewRecaptchaProvider("test-secret", mockHTTP)

	require.NoError(t, err)
	assert.Equal(t, &RecaptchaProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}, provider)
}

func TestRecaptchaProvider_Verify(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		provider, err := NewRecaptchaProvider("test-secret", mockHTTP)
		require.NoError(t, err)

		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *http.Request) { gotReq = r }).Return(nil, errors.New("network error")).Times(1)

		success, err := provider.Verify(t.Context(), "test-response", "192.168.1.1")

		require.NotNil(t, gotReq)
		assert.Equal(t, http.MethodPost, gotReq.Method)
		assert.Equal(t, "https://www.google.com/recaptcha/api/siteverify", gotReq.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", gotReq.Header.Get("Content-Type"))

		assert.Equal(t, false, success)
		require.Error(t, err)
		assert.ErrorContains(t, err, "verification request failed")
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		provider, err := NewRecaptchaProvider("test-secret", mockHTTP)
		require.NoError(t, err)

		response := &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}
		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *http.Request) { gotReq = r }).Return(response, nil).Times(1)

		success, err := provider.Verify(t.Context(), "test-response", "192.168.1.1")

		require.NotNil(t, gotReq)
		assert.Equal(t, http.MethodPost, gotReq.Method)
		assert.Equal(t, "https://www.google.com/recaptcha/api/siteverify", gotReq.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", gotReq.Header.Get("Content-Type"))

		assert.Equal(t, false, success)
		require.Error(t, err)
		assert.ErrorContains(t, err, "API returned status 500")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		provider, err := NewRecaptchaProvider("test-secret", mockHTTP)
		require.NoError(t, err)

		response := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("invalid json"))}
		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *http.Request) { gotReq = r }).Return(response, nil).Times(1)

		success, err := provider.Verify(t.Context(), "test-response", "192.168.1.1")

		require.NotNil(t, gotReq)
		assert.Equal(t, http.MethodPost, gotReq.Method)
		assert.Equal(t, "https://www.google.com/recaptcha/api/siteverify", gotReq.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", gotReq.Header.Get("Content-Type"))

		assert.Equal(t, false, success)
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to parse")
	})

	t.Run("verification failed with error codes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		provider, err := NewRecaptchaProvider("test-secret", mockHTTP)
		require.NoError(t, err)

		response := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":false,"error-codes":["invalid-input-response","timeout-or-duplicate"]}`))}
		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *http.Request) { gotReq = r }).Return(response, nil).Times(1)

		success, err := provider.Verify(t.Context(), "test-response", "192.168.1.1")

		require.NotNil(t, gotReq)
		assert.Equal(t, http.MethodPost, gotReq.Method)
		assert.Equal(t, "https://www.google.com/recaptcha/api/siteverify", gotReq.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", gotReq.Header.Get("Content-Type"))

		assert.Equal(t, false, success)
		require.Error(t, err)
		assert.ErrorContains(t, err, "verification failed")
		assert.ErrorContains(t, err, "invalid-input-response")
	})

	t.Run("successful verification", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockHTTP := mocks.NewMockHTTPClient(ctrl)
		provider, err := NewRecaptchaProvider("test-secret", mockHTTP)
		require.NoError(t, err)

		response := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`))}
		var gotReq *http.Request
		mockHTTP.EXPECT().Do(gomock.Any()).Do(func(r *http.Request) { gotReq = r }).Return(response, nil).Times(1)

		success, err := provider.Verify(t.Context(), "test-response", "192.168.1.1")

		require.NotNil(t, gotReq)
		assert.Equal(t, http.MethodPost, gotReq.Method)
		assert.Equal(t, "https://www.google.com/recaptcha/api/siteverify", gotReq.URL.String())
		assert.Equal(t, "application/x-www-form-urlencoded", gotReq.Header.Get("Content-Type"))

		assert.Equal(t, true, success)
		require.NoError(t, err)
	})
}
