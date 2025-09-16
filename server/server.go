package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/remediation"
	"github.com/kdwils/envoy-proxy-bouncer/remediation/components"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	remediator Remediator
	captcha    Captcha
	config     config.Config
	logger     *slog.Logger
}

func NewServer(config config.Config, remediator Remediator, captcha Captcha, logger *slog.Logger) *Server {
	return &Server{
		config:     config,
		remediator: remediator,
		logger:     logger,
		captcha:    captcha,
	}
}

// ServeDual starts both gRPC and HTTP servers concurrently
func (s *Server) ServeDual(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	grpcPort := s.config.Server.GRPCPort
	if grpcPort == 0 {
		grpcPort = s.config.Server.Port
		if grpcPort == 0 {
			grpcPort = 8080
		}
	}

	httpPort := s.config.Server.HTTPPort
	if httpPort == 0 {
		httpPort = grpcPort + 1
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.logger.Info("starting gRPC server", "port", grpcPort)
		if err := s.serveGRPC(ctx, grpcPort); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	if s.config.Captcha.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info("starting HTTP server", "port", httpPort)
			if err := s.serveHTTP(ctx, httpPort); err != nil {
				errChan <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
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
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down gRPC server...")
		grpcServer.GracefulStop()
		s.logger.Info("gRPC server shutdown complete")
	}()

	return grpcServer.Serve(lis)
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

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: corsHandler,
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

	sessionID := r.FormValue("session")

	var captchaResponse string
	switch s.captcha.GetProviderName() {
	case "recaptcha":
		captchaResponse = r.FormValue("g-recaptcha-response")
	case "hcaptcha":
		captchaResponse = r.FormValue("h-captcha-response")
	case "turnstile":
		captchaResponse = r.FormValue("cf-turnstile-response")
	}

	if sessionID == "" {
		http.Error(w, "session id is required", http.StatusBadRequest)
	}

	if captchaResponse == "" {
		http.Error(w, "captcha response is required", http.StatusBadRequest)
		return
	}

	session, ok := s.captcha.GetSession(sessionID)
	if !ok {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}

	verificationResult, err := s.captcha.VerifyResponse(r.Context(), components.VerificationRequest{
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

	s.captcha.DeleteSession(sessionID)

	http.Redirect(w, r, session.OriginalURL, http.StatusFound)
}

func (s *Server) handleCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.config.Captcha.Enabled {
		http.Error(w, "Captcha not enabled", http.StatusNotFound)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "Missing session parameter", http.StatusBadRequest)
		return
	}

	remediator, ok := s.remediator.(*remediation.Remediator)
	if !ok || remediator.CaptchaService == nil {
		http.Error(w, "Captcha service not available", http.StatusInternalServerError)
		return
	}

	session, exists := remediator.CaptchaService.GetSession(sessionID)
	if !exists {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}

	callbackURL := s.config.Captcha.Hostname + "/captcha"
	html, err := remediator.CaptchaService.Provider.RenderChallenge(
		s.config.Captcha.SiteKey,
		callbackURL,
		session.OriginalURL,
		sessionID,
	)
	if err != nil {
		s.logger.Error("failed to render captcha challenge", "error", err)
		http.Error(w, "Failed to render captcha", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (s *Server) loggerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	reqLogger := slog.New(s.logger.Handler())
	return handler(logger.WithContext(ctx, reqLogger), req)
}

func (s *Server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	if s.remediator == nil {
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "remediator not initialized"), nil
	}
	result := s.remediator.Check(ctx, req)
	s.logger.Info("remediation result", slog.Any("result", result))
	switch result.Action {
	case "allow":
		return getAllowedResponse(), nil
	case "captcha_redirect":
		return getRedirectResponse(result.RedirectURL), nil
	case "deny", "ban":
		return getDeniedResponse(envoy_type.StatusCode_Forbidden, result.Reason), nil
	case "error":
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, result.Reason), nil
	default:
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "unknown action"), nil
	}
}

func getAllowedResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: 0,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{},
	}
}

func getDeniedResponse(code envoy_type.StatusCode, body string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(code),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: code,
				},
				Body: body,
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
