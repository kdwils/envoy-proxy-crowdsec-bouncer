package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

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
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func getDefaultConfig() config.Config {
	return config.Config{
		Templates: config.Templates{
			DeniedTemplateHeaders:  "text/plain; charset=utf-8",
			CaptchaTemplateHeaders: "text/html; charset=utf-8",
		},
	}
}

func TestServer_Check(t *testing.T) {
	log := logger.FromContext(context.Background())
	t.Run("bouncer not initialized", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)
		mockTemplateStore.EXPECT().RenderDenied(gomock.Any()).Return("rendered template content", nil)
		s := NewServer(getDefaultConfig(), nil, nil, mockTemplateStore, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
			assert.Equal(t, "rendered template content", deny.Body)
		}
	})

	t.Run("request blocked with template", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

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

		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)
		mockTemplateStore.EXPECT().RenderDenied(gomock.Any()).Return("mocked template content", nil)
		s := NewServer(getDefaultConfig(), mockBouncer, nil, mockTemplateStore, log)
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
			assert.Equal(t, "mocked template content", deny.Body)
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
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

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})

		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "test error")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
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
		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)
		mockTemplateStore.EXPECT().RenderDenied(gomock.Any()).Return("Access Blocked", nil)

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mockTemplateStore, log)
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
			assert.Equal(t, "text/plain; charset=utf-8", value)
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

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)
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

	t.Run("template rendering with real template store", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

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
			ParsedRequest: &bouncer.ParsedRequest{
				Method: "GET",
				URL: url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/blocked",
				},
			},
		})

		templateStore, err := template.NewStore(template.Config{})
		if err != nil {
			t.Fatalf("failed to create template store: %v", err)
		}

		s := NewServer(getDefaultConfig(), mockBouncer, nil, templateStore, log)
		fixedTime := time.Date(2023, 12, 25, 10, 30, 0, 0, time.UTC)
		s.now = func() time.Time { return fixedTime }
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
							":method":    "GET",
							":path":      "/blocked",
							":scheme":    "http",
							":authority": "example.com",
						},
					},
				},
			},
		}

		resp, err := s.Check(context.Background(), req)

		expectedHTML, err := os.ReadFile("testing/denied_with_template.html")
		if err != nil {
			t.Fatalf("failed to read expected HTML: %v", err)
		}

		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Equal(t, string(expectedHTML), deny.Body)
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
		}
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

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(500), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "remediator error")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
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
		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)
		mockTemplateStore.EXPECT().RenderDenied(gomock.Any()).Return("Access Blocked", nil)

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mockTemplateStore, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(403), resp.Status.Code)
		deny := resp.GetDeniedResponse()
		if assert.NotNil(t, deny) {
			assert.Contains(t, deny.Body, "Access Blocked")
			value, ok := findHeader(deny.Headers, "Content-Type")
			assert.True(t, ok)
			assert.Equal(t, "text/plain; charset=utf-8", value)
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

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.Status.Code)
		assert.Nil(t, resp.GetDeniedResponse())
	})

	t.Run("remediator returns captcha", func(t *testing.T) {
		log := logger.FromContext(context.Background())
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		session := &components.CaptchaSession{
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			CallbackURL: "http://example.com/captcha",
			RedirectURL: "http://example.com/original",
			ID:          "test-session",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockBouncer.EXPECT().Check(gomock.Any(), gomock.Any()).Return(bouncer.CheckedRequest{
			Action:         "captcha",
			Reason:         "captcha required",
			HTTPStatus:     302,
			CaptchaSession: session,
		})

		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mockTemplateStore, log)
		resp, err := s.Check(context.Background(), &auth.CheckRequest{})
		assert.NoError(t, err)
		assert.Equal(t, int32(envoy_type.StatusCode_Found), resp.Status.Code)

		deniedResp := resp.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, envoy_type.StatusCode_Found, deniedResp.Status.Code)
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
		mockTemplateStore := mocks.NewMockTemplateStore(ctrl)
		mockTemplateStore.EXPECT().RenderDenied(gomock.Any()).Return("Access Blocked", nil)

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mockTemplateStore, log)
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

		s := NewServer(getDefaultConfig(), mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)
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
				GRPCPort: 8080,
			},
		}

		server := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("g-recaptcha-response", "test-response")

		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.handleCaptchaVerify(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "session id is required")
	})

	t.Run("missing csrf token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}

		session := &components.CaptchaSession{
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CallbackURL: "http://example.com/captcha",
			RedirectURL: "http://example.com/original",
			ID:          "test-session",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("test-session").Times(1).Return(session, true)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "test-session")

		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.handleCaptchaVerify(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "CSRF token is required")
	})

	t.Run("invalid csrf token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}

		session := &components.CaptchaSession{
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CallbackURL: "http://example.com/captcha",
			RedirectURL: "http://example.com/original",
			ID:          "test-session",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("test-session").Times(1).Return(session, true)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "test-session")
		form.Add("csrf_token", "invalid-token")

		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.handleCaptchaVerify(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid CSRF token")
	})

	t.Run("missing captcha response - recaptcha", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cfg := config.Config{
			Captcha: config.Captcha{
				Enabled: true,
			},
		}

		session := &components.CaptchaSession{
			IP:          "192.0.2.1",
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CallbackURL: "http://example.com/captcha",
			RedirectURL: "http://example.com/original",
			ID:          "test-session",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("test-session").Times(1).Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("192.0.2.1")

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "test-session")
		form.Add("csrf_token", "valid-csrf-token")

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

		session := &components.CaptchaSession{
			IP:          "192.0.2.1",
			Provider:    "turnstile",
			SiteKey:     "test-site-key",
			CallbackURL: "http://example.com/captcha",
			RedirectURL: "http://example.com/original",
			ID:          "test-session",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("test-session").Times(1).Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("192.0.2.1")

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "test-session")
		form.Add("csrf_token", "valid-csrf-token")

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
		mockCaptcha.EXPECT().GetSession("invalid-session").Return(nil, false)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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
			ID:          "test-session",
			Provider:    "recaptcha",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("192.168.1.1")
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), "test-session", components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(nil, assert.AnError)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("csrf_token", "valid-csrf-token")
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
			ID:          "test-session",
			Provider:    "recaptcha",
			CSRFToken:   "valid-csrf-token",
		}

		verificationResult := &components.VerificationResult{
			Success: false,
			Message: "Verification failed",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("192.168.1.1")
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), "test-session", components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("csrf_token", "valid-csrf-token")
		form.Add("g-recaptcha-response", "test-response")

		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.handleCaptchaVerify(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Verification failed")
	})

	t.Run("IP mismatch", func(t *testing.T) {
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
			ID:          "test-session",
			Provider:    "recaptcha",
			CSRFToken:   "valid-csrf-token",
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("10.0.0.1")

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("csrf_token", "valid-csrf-token")
		form.Add("g-recaptcha-response", "test-response")

		req := httptest.NewRequest("POST", "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.handleCaptchaVerify(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "IP address mismatch")
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
			ID:          "test-session",
			Provider:    "recaptcha",
			CSRFToken:   "valid-csrf-token",
		}

		verificationResult := &components.VerificationResult{
			Success: true,
		}

		mockBouncer := mocks.NewMockBouncer(ctrl)
		mockCaptcha := remediationmocks.NewMockCaptchaService(ctrl)
		mockCaptcha.EXPECT().GetSession("valid-session").Return(session, true)
		mockBouncer.EXPECT().ExtractRealIPFromHTTP(gomock.Any()).Return("192.168.1.1")
		mockCaptcha.EXPECT().VerifyResponse(gomock.Any(), "test-session", components.VerificationRequest{
			Response: "test-response",
			IP:       "192.168.1.1",
		}).Return(verificationResult, nil)

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

		form := url.Values{}
		form.Add("session", "valid-session")
		form.Add("csrf_token", "valid-csrf-token")
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

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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

		s := NewServer(cfg, mockBouncer, mockCaptcha, mocks.NewMockTemplateStore(ctrl), log)

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
