package components

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	mocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/components/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewTurnstileProvider(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider, err := NewTurnstileProvider("test-secret", mockHTTP)

		assert.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "test-secret", provider.SecretKey)
		assert.Equal(t, mockHTTP, provider.HTTPClient)
	})
}

func TestTurnstileProvider_GetProviderName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockHTTP := mocks.NewMockHTTPClient(ctrl)

	provider := &TurnstileProvider{SecretKey: "test", HTTPClient: mockHTTP}

	assert.Equal(t, "turnstile", provider.GetProviderName())
}

func TestTurnstileProvider_Verify(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider := &TurnstileProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}

		expectedMatcher := httpReqMatcher{
			method: "POST",
			urlStr: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		mockHTTP.EXPECT().Do(expectedMatcher).Return(nil, errors.New("network error")).Times(1)

		success, err := provider.Verify(context.Background(), "test-response", "192.168.1.1")

		assert.Error(t, err)
		assert.False(t, success)
		assert.Contains(t, err.Error(), "turnstile verification request failed")
	})

	t.Run("non-OK status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider := &TurnstileProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}

		response := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader("")),
		}

		expectedMatcher := httpReqMatcher{
			method: "POST",
			urlStr: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		mockHTTP.EXPECT().Do(expectedMatcher).Return(response, nil).Times(1)

		success, err := provider.Verify(context.Background(), "test-response", "192.168.1.1")

		assert.Error(t, err)
		assert.False(t, success)
		assert.Contains(t, err.Error(), "turnstile API returned status 500")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider := &TurnstileProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}

		response := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("invalid json")),
		}

		expectedMatcher := httpReqMatcher{
			method: "POST",
			urlStr: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		mockHTTP.EXPECT().Do(expectedMatcher).Return(response, nil).Times(1)

		success, err := provider.Verify(context.Background(), "test-response", "192.168.1.1")

		assert.Error(t, err)
		assert.False(t, success)
		assert.Contains(t, err.Error(), "failed to parse turnstile response")
	})

	t.Run("verification failed with error codes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider := &TurnstileProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}

		respBody := `{"success":false,"error-codes":["invalid-input-response","bad-request"]}`
		response := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(respBody)),
		}

		expectedMatcher := httpReqMatcher{
			method: "POST",
			urlStr: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		mockHTTP.EXPECT().Do(expectedMatcher).Return(response, nil).Times(1)

		success, err := provider.Verify(context.Background(), "test-response", "192.168.1.1")

		assert.Error(t, err)
		assert.False(t, success)
		assert.Contains(t, err.Error(), "turnstile verification failed")
		assert.Contains(t, err.Error(), "invalid-input-response")
	})

	t.Run("successful verification", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHTTP := mocks.NewMockHTTPClient(ctrl)

		provider := &TurnstileProvider{SecretKey: "test-secret", HTTPClient: mockHTTP}

		respBody := `{"success":true,"challenge_ts":"2023-01-01T00:00:00Z","hostname":"example.com","action":"login","cdata":"data"}`
		response := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(respBody)),
		}

		expectedMatcher := httpReqMatcher{
			method: "POST",
			urlStr: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		mockHTTP.EXPECT().Do(expectedMatcher).Return(response, nil).Times(1)

		success, err := provider.Verify(context.Background(), "test-response", "192.168.1.1")

		assert.NoError(t, err)
		assert.True(t, success)
	})
}
