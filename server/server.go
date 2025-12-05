package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	healthCheckServiceLiveness  = "liveness"
	healthCheckServiceReadiness = "readiness"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	bouncer       Bouncer
	captcha       Captcha
	config        config.Config
	logger        *slog.Logger
	templateStore TemplateStore
	now           func() time.Time
	rateLimiter   *RateLimiter
	healthServer  *health.Server
}

func NewServer(config config.Config, bouncer Bouncer, captcha Captcha, templateStore TemplateStore, logger *slog.Logger) *Server {
	healthServer := health.NewServer()
	healthServer.SetServingStatus(healthCheckServiceLiveness, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(healthCheckServiceReadiness, grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	return &Server{
		config:        config,
		bouncer:       bouncer,
		logger:        logger,
		captcha:       captcha,
		templateStore: templateStore,
		now:           time.Now,
		rateLimiter:   NewRateLimiter(10, 20),
		healthServer:  healthServer,
	}
}

// ServeDual starts both gRPC and HTTP servers concurrently
func (s *Server) ServeDual(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	grpcPort := s.config.Server.GRPCPort
	httpPort := s.config.Server.HTTPPort

	wg.Go(func() {
		s.logger.Info("starting gRPC server", "port", grpcPort)
		if err := s.serveGRPC(ctx, grpcPort); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	})

	if s.config.Captcha.Enabled {
		wg.Go(func() {
			s.logger.Info("starting HTTP server", "port", httpPort)
			if err := s.serveHTTP(ctx, httpPort); err != nil {
				errChan <- fmt.Errorf("HTTP server error: %w", err)
			}
		})
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Serve provides backward compatibility - serves only gRPC
func (s *Server) Serve(ctx context.Context, port int) error {
	return s.serveGRPC(ctx, port)
}

func (s *Server) serveGRPC(ctx context.Context, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %v", port, err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(s.loggerInterceptor),
	)
	auth.RegisterAuthorizationServer(grpcServer, s)
	grpc_health_v1.RegisterHealthServer(grpcServer, s.healthServer)
	reflection.Register(grpcServer)

	go s.updateHealthStatus(ctx)

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down gRPC server...")
		grpcServer.GracefulStop()
		s.logger.Info("gRPC server shutdown complete")
	}()

	return grpcServer.Serve(lis)
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.bouncer.ExtractRealIPFromHTTP(r)
		if !s.rateLimiter.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveHTTP(ctx context.Context, port int) error {
	r := mux.NewRouter()
	r.HandleFunc("/captcha/verify", s.handleCaptchaVerify).Methods("POST", "OPTIONS")
	r.HandleFunc("/captcha/challenge", s.handleCaptchaChallenge).Methods("GET")

	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)(r)

	rateLimitedHandler := s.rateLimitMiddleware(corsHandler)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: rateLimitedHandler,
	}

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down HTTP server...")
		httpServer.Shutdown(context.Background())
		s.logger.Info("HTTP server shutdown complete")
	}()

	s.logger.Info("HTTP server listening", "addr", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed: %v", err)
	}
	return nil
}

func (s *Server) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if !s.config.Captcha.Enabled {
		http.Error(w, "Captcha not enabled", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	challengeToken := r.FormValue("session")
	if challengeToken == "" {
		http.Error(w, "session id is required", http.StatusBadRequest)
		return
	}

	session, ok := s.captcha.GetSession(challengeToken)
	if !ok {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}

	clientIP := s.bouncer.ExtractRealIPFromHTTP(r)
	if clientIP != session.IP {
		s.logger.Warn("IP mismatch during captcha verification", "session_ip", session.IP, "client_ip", clientIP)
		http.Error(w, "IP address mismatch", http.StatusForbidden)
		return
	}

	var captchaResponse string
	switch strings.ToLower(session.Provider) {
	case "recaptcha":
		captchaResponse = r.FormValue("g-recaptcha-response")
	case "turnstile":
		captchaResponse = r.FormValue("cf-turnstile-response")
	}

	if captchaResponse == "" {
		http.Error(w, "captcha response is required", http.StatusBadRequest)
		return
	}

	verificationResult, err := s.captcha.VerifyResponse(r.Context(), challengeToken, components.VerificationRequest{
		Response: captchaResponse,
		IP:       session.IP,
	})
	if err != nil {
		s.logger.Error("captcha verification error", "error", err)
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	if !verificationResult.Success {
		http.Error(w, verificationResult.Message, http.StatusForbidden)
		return
	}

	sameSite := http.SameSiteLaxMode
	if s.config.Captcha.SecureCookie {
		sameSite = http.SameSiteNoneMode
	}

	cookie := &http.Cookie{
		Name:     "captcha_verified",
		Value:    verificationResult.Token,
		Path:     "/",
		Domain:   s.config.Captcha.CookieDomain,
		HttpOnly: true,
		Secure:   s.config.Captcha.SecureCookie,
		SameSite: sameSite,
		MaxAge:   int(s.config.Captcha.SessionDuration.Seconds()),
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, session.OriginalURL, http.StatusFound)
}

func (s *Server) handleCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.config.Captcha.Enabled {
		http.Error(w, "Captcha not enabled", http.StatusNotFound)
		return
	}

	if s.templateStore == nil {
		s.logger.Error("template store not available")
		http.Error(w, "Template store not available", http.StatusInternalServerError)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "Missing session parameter", http.StatusBadRequest)
		return
	}

	if s.captcha == nil {
		http.Error(w, "Captcha service not available", http.StatusInternalServerError)
		return
	}

	session, exists := s.captcha.GetSession(sessionID)
	if !exists {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}
	if session == nil {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}

	data := template.CaptchaTemplateData{
		Provider:    session.Provider,
		SiteKey:     session.SiteKey,
		CallbackURL: session.CallbackURL,
		RedirectURL: session.RedirectURL,
		SessionID:   session.ID,
	}

	html, err := s.templateStore.RenderCaptcha(data)
	if err != nil {
		s.logger.Error("failed to render captcha challenge", "error", err)
		http.Error(w, "Failed to render captcha", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", s.config.Templates.CaptchaTemplateHeaders)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (s *Server) updateHealthStatus(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.isReady() {
				s.healthServer.SetServingStatus(healthCheckServiceReadiness, grpc_health_v1.HealthCheckResponse_SERVING)
				return
			}
		}
	}
}

func (s *Server) isReady() bool {
	if s.bouncer == nil {
		return false
	}

	return s.bouncer.IsReady()
}

func (s *Server) loggerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	reqLogger := slog.New(s.logger.Handler())
	return handler(logger.WithContext(ctx, reqLogger), req)
}

func (s *Server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	if s.bouncer == nil {
		body, headers := s.renderDeniedResponse(bouncer.NewCheckedRequest("", "", "remediator not initialized", 0, nil, "", nil, nil))
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, body, headers), nil
	}

	result := s.bouncer.Check(ctx, req)
	s.logger.Info("remediation result", slog.Any("result", result))
	switch result.Action {
	case "allow":
		return getAllowedResponse(), nil
	case "captcha":
		return getRedirectResponse(result.RedirectURL), nil
	case "deny", "ban":
		body, headers := s.renderDeniedResponse(result)
		return getDeniedResponse(httpStatusToEnvoyStatus(result.HTTPStatus), body, headers), nil
	case "error":
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, result.Reason, map[string]string{"Content-Type": s.config.Templates.DeniedTemplateHeaders}), nil
	default:
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "unknown action", map[string]string{"Content-Type": s.config.Templates.DeniedTemplateHeaders}), nil
	}
}

func (s *Server) renderDeniedResponse(result bouncer.CheckedRequest) (string, map[string]string) {
	contentType := s.config.Templates.DeniedTemplateHeaders
	headers := map[string]string{"Content-Type": contentType}

	if s.templateStore == nil {
		reason := result.Reason
		if reason == "" {
			reason = "access denied"
		}
		return reason, headers
	}

	data := s.buildDeniedTemplateData(result)
	body, err := s.templateStore.RenderDenied(data)
	if err != nil {
		s.logger.Error("failed to render denied response template", "error", err)
		reason := result.Reason
		if reason == "" {
			reason = "access denied"
		}
		return reason, headers
	}

	return body, headers
}

func (s *Server) buildDeniedTemplateData(result bouncer.CheckedRequest) template.DeniedTemplateData {
	data := template.DeniedTemplateData{
		IP:        result.IP,
		Reason:    result.Reason,
		Action:    result.Action,
		Timestamp: s.now().UTC(),
		Decision:  result.Decision,
	}

	if result.ParsedRequest == nil {
		return data
	}

	parsed := result.ParsedRequest

	data.Request = template.DeniedRequest{
		Method:   parsed.Method,
		Path:     parsed.URL.Path,
		Host:     parsed.URL.Host,
		Scheme:   parsed.URL.Scheme,
		Protocol: fmt.Sprintf("HTTP/%d.%d", parsed.ProtoMajor, parsed.ProtoMinor),
		URL:      parsed.URL.String(),
	}

	return data
}

func buildHeaderValues(headers map[string]string) []*envoy_core.HeaderValueOption {
	if len(headers) == 0 {
		return nil
	}

	values := make([]*envoy_core.HeaderValueOption, 0, len(headers))
	for k, v := range headers {
		key := k
		value := v
		values = append(values, &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   key,
				Value: value,
			},
		})
	}

	return values
}

func httpStatusToEnvoyStatus(httpStatus int) envoy_type.StatusCode {
	return envoy_type.StatusCode(httpStatus)
}

func getAllowedResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: 0,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{},
	}
}

func getDeniedResponse(code envoy_type.StatusCode, body string, headers map[string]string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(code),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: code,
				},
				Body:    body,
				Headers: buildHeaderValues(headers),
			},
		},
	}
}

func getRedirectResponse(location string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(envoy_type.StatusCode_Found),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*envoy_core.HeaderValueOption{
					{
						Header: &envoy_core.HeaderValue{
							Key:   "Location",
							Value: location,
						},
					},
				},
			},
		},
	}
}
