package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	remediationmocks "github.com/kdwils/envoy-proxy-bouncer/bouncer/mocks"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
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
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, templateDeniedContentType, value)
			assert.Contains(t, deny.Body, "Access Blocked")
		}
	})

	t.Run("request blocked with template", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tmpl := "<html><body><h1>Access Denied</h1><p>IP: {{ .IP }}</p><p>Scenario: {{ .Decision.Scenario }}</p><p>Path: {{ .Request.Path }}</p></body></html>"
		dir := t.TempDir()
		path := filepath.Join(dir, "ban.html")
		if err := os.WriteFile(path, []byte(tmpl), 0o644); err != nil {
			t.Fatalf("failed to write template: %v", err)
		}

		cfg := config.Config{
			Server: config.Server{
				BanTemplatePath: path,
			},
		}

		decision := &models.Decision{
			Type:     strPtr("ban"),
			Scenario: strPtr("crowdsecurity/http-bad"),
			Origin:   strPtr("CAPI"),
			Duration: strPtr("1h"),
			Scope:    strPtr("Ip"),
			Value:    strPtr("192.0.2.1"),
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "ban",
			Reason:     "crowdsecurity/http-bad",
			HTTPStatus: 403,
			Decision:   decision,
			IP:         "192.0.2.1",
		})

		s := NewServer(cfg, mockBouncer, nil, log)
		req := &auth.CheckRequest{
			Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{Address: "192.0.2.1"},
						},
					},
				},
				Request: &auth.AttributeContext_Request{
					Http: &auth.AttributeContext_HttpRequest{
						Headers: map[string]string{
							":method": "GET",
							":path":   "/blocked",
						},
					},
				},
			},
		}

		resp, err := s.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			expectedBody := "<html><body><h1>Access Denied</h1><p>IP: 192.0.2.1</p><p>Scenario: crowdsecurity/http-bad</p><p>Path: /blocked</p></body></html>"
			assert.Equal(t, expectedBody, deny.Body)
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, templateDeniedContentType, value)
		}
	})

	t.Run("bouncer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "error",
			Reason:     "test error",
			HTTPStatus: 500,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "test error")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, defaultDeniedContentType, value)
		}
	})

	t.Run("request blocked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "deny",
			Reason:     "blocked",
			HTTPStatus: 403,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
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
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, templateDeniedContentType, value)
			assert.Contains(t, deny.Body, "Access Blocked")
		}
	})

	t.Run("request allowed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
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

func TestServer_Check_WithBouncer(t *testing.T) {
	t.Run("remediator returns error", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)

		defer ctrl.Finish()
		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "error",
			Reason:     "remediator error",
			HTTPStatus: 500,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "remediator error")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, defaultDeniedContentType, value)
		}
	})

	t.Run("remediator returns deny", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "deny",
			Reason:     "blocked",
			HTTPStatus: 403,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "Access Blocked")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, templateDeniedContentType, value)
		}
	})

	t.Run("remediator returns allow", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "allow",
			Reason:     "ok",
			HTTPStatus: 200,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.Status.Code)
		assert.Nil(t, resp.GetDeniedResponse())
	})

	t.Run("remediator returns captcha", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:      "captcha",
			Reason:      "captcha required",
			RedirectURL: "http://example.com/captcha",
			HTTPStatus:  302,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "ban",
			Reason:     "IP banned",
			HTTPStatus: 403,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		assert.Contains(t, resp.GetDeniedResponse().Body, "Access Blocked")
	})

	t.Run("remediator returns unknown action", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:     "unknown",
			Reason:     "unexpected action",
			HTTPStatus: 500,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(config.Config{}, mockBouncer, mockCaptcha, log)
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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		cfg := config.Config{
			Server: config.Server{
				Port: 8080,
			},
		}

		server := NewServer(cfg, mockBouncer, mockCaptcha, log)

		assert.NotNil(t, server)
		assert.Equal(t, cfg, server.config)
		assert.Equal(t, mockBouncer, server.bouncer)
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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha").AnyTimes()

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("turnstile")

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("invalid-session").Return(nil, false)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(nil, assert.AnError)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetProviderName().Return("recaptcha")
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)
		mockCaptcha.EXPECT().DeleteSession("valid-session")

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)

		s := NewServer(cfg, mockBouncer, mockCaptcha, log)

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

		resp := getDeniedResponse(code, body, nil)

		assert.NotNil(t, resp)
		assert.Equal(t, int32(code), resp.Status.Code)

		deniedResp := resp.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, code, deniedResp.Status.Code)
		assert.Equal(t, body, deniedResp.Body)
		assert.Len(t, deniedResp.Headers, 0)
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

func findHeader(headers []*core.HeaderValueOption, key string) (string, bool) {
	for _, h := range headers {
		if h == nil || h.Header == nil {
			continue
		}
		if strings.EqualFold(h.Header.Key, key) {
			return h.Header.Value, true
		}
	}
	return "", false
}

func strPtr(s string) *string {
	return &s
}
