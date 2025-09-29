package server

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer/components"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

//go:embed templates/ban.html
var defaultBanTemplate string

const (
	defaultDeniedContentType  = "text/plain; charset=utf-8"
	templateDeniedContentType = "text/html; charset=utf-8"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	bouncer           Bouncer
	captcha           Captcha
	config            config.Config
	logger            *slog.Logger
	deniedTemplate    *template.Template
	deniedContentType string
}

func NewServer(config config.Config, bouncer Bouncer, captcha Captcha, logger *slog.Logger) *Server {
	s := &Server{
		config:  config,
		bouncer: bouncer,
		logger:  logger,
		captcha: captcha,
	}

	s.deniedTemplate, s.deniedContentType = s.loadDeniedTemplate()
	if s.deniedTemplate == nil {
		s.deniedContentType = defaultDeniedContentType
	}

	return s
}

func (s *Server) loadDeniedTemplate() (*template.Template, string) {
	templateContent := defaultBanTemplate
	templateSource := "embedded"
	s.logger.Info("using embedded ban template")

	if s.config.Server.BanTemplatePath != "" {
		content, err := os.ReadFile(s.config.Server.BanTemplatePath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				s.logger.Error("failed to read denied response template", "path", s.config.Server.BanTemplatePath, "error", err)
			}
			s.logger.Info("using embedded ban template as fallback")
			return s.parseTemplate(templateContent, templateSource)
		}
		templateContent = string(content)
		templateSource = s.config.Server.BanTemplatePath
		s.logger.Info("loaded custom ban template", "path", s.config.Server.BanTemplatePath)
	}

	return s.parseTemplate(templateContent, templateSource)
}

func (s *Server) parseTemplate(content, source string) (*template.Template, string) {
	tmpl, err := template.New("denied_response").Parse(content)
	if err != nil {
		s.logger.Error("failed to parse denied response template", "source", source, "error", err)
		return nil, ""
	}
	return tmpl, templateDeniedContentType
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
	case "turnstile":
		captchaResponse = r.FormValue("cf-turnstile-response")
	}

	if sessionID == "" {
		http.Error(w, "session id is required", http.StatusBadRequest)
		return
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

	if s.captcha == nil {
		http.Error(w, "Captcha service not available", http.StatusInternalServerError)
		return
	}

	session, exists := s.captcha.GetSession(sessionID)
	if !exists {
		http.Error(w, "Invalid or expired session", http.StatusForbidden)
		return
	}

	callbackURL := s.config.Captcha.CallbackURL + "/captcha"
	html, err := s.captcha.RenderChallenge(
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
	if s.bouncer == nil {
		body, headers := s.renderDeniedResponse(bouncer.CheckedRequest{Reason: "remediator not initialized"}, req)
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
		body, headers := s.renderDeniedResponse(result, req)
		return getDeniedResponse(envoy_type.StatusCode_Forbidden, body, headers), nil
	case "error":
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, result.Reason, map[string]string{"Content-Type": defaultDeniedContentType}), nil
	default:
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "unknown action", map[string]string{"Content-Type": defaultDeniedContentType}), nil
	}
}

func (s *Server) renderDeniedResponse(result bouncer.CheckedRequest, req *auth.CheckRequest) (string, map[string]string) {
	if s.deniedTemplate == nil {
		reason := result.Reason
		if reason == "" {
			reason = "access denied"
		}
		return reason, map[string]string{"Content-Type": defaultDeniedContentType}
	}

	data := buildDeniedTemplateData(result, req)
	var buf bytes.Buffer
	if err := s.deniedTemplate.Execute(&buf, data); err != nil {
		s.logger.Error("failed to render denied response template", "error", err)
		reason := result.Reason
		if reason == "" {
			reason = "access denied"
		}
		return reason, map[string]string{"Content-Type": defaultDeniedContentType}
	}

	return buf.String(), map[string]string{"Content-Type": s.deniedContentType}
}

type deniedRequestData struct {
	Method   string
	Path     string
	Host     string
	Scheme   string
	Protocol string
	URL      string
	Headers  map[string]string
}

type deniedTemplateData struct {
	IP        string
	Reason    string
	Action    string
	Timestamp time.Time
	Request   deniedRequestData
	Decision  *models.Decision
}

func buildDeniedTemplateData(result bouncer.CheckedRequest, req *auth.CheckRequest) deniedTemplateData {
	data := deniedTemplateData{
		IP:        result.IP,
		Reason:    result.Reason,
		Action:    result.Action,
		Timestamp: time.Now().UTC(),
		Decision:  result.Decision,
	}

	data.Request.Headers = map[string]string{}

	if req == nil {
		return data
	}

	attrs := req.GetAttributes()
	if attrs == nil {
		return data
	}

	reqAttr := attrs.GetRequest()
	if reqAttr == nil {
		return data
	}

	httpReq := reqAttr.GetHttp()
	if httpReq == nil {
		return data
	}

	headers := make(map[string]string, len(httpReq.GetHeaders()))
	for k, v := range httpReq.GetHeaders() {
		headers[k] = v
	}

	method := headers[":method"]
	path := headers[":path"]
	host := headers[":authority"]
	scheme := headers[":scheme"]
	proto := httpReq.GetProtocol()

	url := ""
	if scheme != "" && host != "" {
		url = fmt.Sprintf("%s://%s%s", scheme, host, path)
	}

	data.Request = deniedRequestData{
		Method:   method,
		Path:     path,
		Host:     host,
		Scheme:   scheme,
		Protocol: proto,
		URL:      url,
		Headers:  headers,
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
