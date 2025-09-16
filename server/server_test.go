package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/remediation"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/components"
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

	t.Run("remediator returns captcha", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:      "captcha",
			Reason:      "captcha required",
			RedirectURL: "http://example.com/captcha",
			HTTPStatus:  302,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(envoy_type.StatusCode_Found), resp.Status.Code)
		deniedResp := resp.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, envoy_type.StatusCode_Found, deniedResp.Status.Code)
		
		found := false
		for _, header := range deniedResp.Headers {
			if header.Header.Key == "Location" {
				assert.Equal(t, "http://example.com/captcha", header.Header.Value)
				found = true
				break
			}
		}
		assert.True(t, found, "Location header not found")
	})

	t.Run("remediator returns ban", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "ban",
			Reason:     "IP banned",
			HTTPStatus: 403,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "IP banned")
	})

	t.Run("remediator returns unknown action", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockRemediator.EXPECT().Check(gomock.Any(), gomock.Any()).Return(remediation.CheckedRequest{
			Action:     "unknown",
			Reason:     "unexpected action",
			HTTPStatus: 500,
		})

		mockCaptcha := mocks.NewMockCaptcha(ctrl)

		s := NewServer(config.Config{}, mockRemediator, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(envoy_type.StatusCode_InternalServerError), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "unknown action")
	})
}

func TestServer_NewServer(t *testing.T) {
	t.Run("creates server with all dependencies", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		cfg := config.Config{
			Server: config.Server{
				Port: 8080,
			},
		}

		server := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		assert.NotNil(t, server)
		assert.Equal(t, cfg, server.config)
		assert.Equal(t, mockRemediator, server.remediator)
		assert.Equal(t, mockCaptcha, server.captcha)
		assert.Equal(t, log, server.logger)
	})
}

func TestServer_handleCaptchaVerify(t *testing.T) {
	log := logger.FromContext(context.Background())

	t.Run("captcha disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: false,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		req := httptest.NewRequest("POST", "/captcha/verify", nil)
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "Captcha not enabled")
	})

	t.Run("form parse error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		// Create a request with an invalid content-type that will cause ParseForm to fail
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader("invalid=data&more=data"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Failed to parse form")
	})

	t.Run("missing session parameter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("g-recaptcha-response", "test-response")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "session id is required")
	})

	t.Run("missing captcha response - recaptcha", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "test-session")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "captcha response is required")
	})

	t.Run("missing captcha response - hcaptcha", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("hcaptcha")
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "test-session")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "captcha response is required")
	})

	t.Run("missing captcha response - turnstile", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("turnstile")
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "test-session")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "captcha response is required")
	})

	t.Run("invalid session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("invalid-session").Return(nil, false)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "invalid-session")
		form.Add("g-recaptcha-response", "test-response")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid or expired session")
	})

	t.Run("verification error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		session := &components.CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(nil, assert.AnError)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("g-recaptcha-response", "test-response")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Verification failed")
	})

	t.Run("verification failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		session := &components.CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com",
		}
		
		verificationResult := &components.VerificationResult{
			Success: false,
			Message: "Verification failed",
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("g-recaptcha-response", "test-response")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Verification failed")
	})

	t.Run("successful verification", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		session := &components.CaptchaSession{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/original",
		}
		
		verificationResult := &components.VerificationResult{
			Success: true,
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)
		mockCaptcha.EXPECT().DeleteSession("valid-session")
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("g-recaptcha-response", "test-response")
		
		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		
		s.handleCaptchaVerify(w, req)
		
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/original", w.Header().Get("Location"))
	})
}

func TestServer_handleCaptchaChallenge(t *testing.T) {
	log := logger.FromContext(context.Background())

	t.Run("captcha disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: false,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		req := httptest.NewRequest("GET", "/captcha/challenge", nil)
		w := httptest.NewRecorder()
		
		s.handleCaptchaChallenge(w, req)
		
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "Captcha not enabled")
	})

	t.Run("missing session parameter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}
		
		mockRemediator := mocks.NewMockRemediator(ctrl)
		mockCaptcha := mocks.NewMockCaptcha(ctrl)
		
		s := NewServer(cfg, mockRemediator, mockCaptcha, log)
		
		req := httptest.NewRequest("GET", "/captcha/challenge", nil)
		w := httptest.NewRecorder()
		
		s.handleCaptchaChallenge(w, req)
		
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Missing session parameter")
	})
}

func TestServer_getAllowedResponse(t *testing.T) {
	t.Run("creates correct allowed response", func(t *testing.T) {
		resp := getAllowedResponse()
		
		assert.NotNil(t, resp)
		assert.Equal(t, int32(0), resp.Status.Code)
		assert.NotNil(t, resp.HttpResponse)
		assert.Nil(t, resp.GetDeniedResponse())
	})
}

func TestServer_getDeniedResponse(t *testing.T) {
	t.Run("creates correct denied response", func(t *testing.T) {
		code := envoy_type.StatusCode_Forbidden
		body := "Access denied"
		
		resp := getDeniedResponse(code, body)
		
		assert.NotNil(t, resp)
		assert.Equal(t, int32(code), resp.Status.Code)
		
		deniedResp := resp.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, code, deniedResp.Status.Code)
		assert.Equal(t, body, deniedResp.Body)
	})
}

func TestServer_getRedirectResponse(t *testing.T) {
	t.Run("creates correct redirect response", func(t *testing.T) {
		location := "http://example.com/redirect"
		
		resp := getRedirectResponse(location)
		
		assert.NotNil(t, resp)
		assert.Equal(t, int32(envoy_type.StatusCode_Found), resp.Status.Code)
		
		deniedResp := resp.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, envoy_type.StatusCode_Found, deniedResp.Status.Code)
		
		found := false
		for _, header := range deniedResp.Headers {
			if header.Header.Key == "Location" {
				assert.Equal(t, location, header.Header.Value)
				found = true
				break
			}
		}
		assert.True(t, found, "Location header not found")
	})
}
