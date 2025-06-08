package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	bouncer bouncer.Bouncer
	config  config.Config
	logger  *slog.Logger
}

func NewServer(config config.Config, bouncer bouncer.Bouncer, logger *slog.Logger) *Server {
	return &Server{
		config:  config,
		bouncer: bouncer,
		logger:  logger,
	}
}

func (s *Server) Serve(ctx context.Context, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
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

func (s *Server) loggerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	reqLogger := slog.New(s.logger.Handler())
	return handler(logger.WithContext(ctx, reqLogger), req)
}

func (s *Server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	logger := logger.FromContext(ctx)
	if s.bouncer == nil {
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "internal server error"), nil
	}

	ip := ""
	if req.Attributes != nil && req.Attributes.Source != nil && req.Attributes.Source.Address != nil {
		if socketAddress := req.Attributes.Source.Address.GetSocketAddress(); socketAddress != nil {
			ip = socketAddress.GetAddress()
		}
	}

	headers := make(map[string]string)
	if req.Attributes != nil && req.Attributes.Request != nil && req.Attributes.Request.Http != nil {
		headers = req.Attributes.Request.Http.Headers
	}

	bounce, err := s.bouncer.Bounce(ctx, ip, headers)
	if err != nil {
		logger.Error("bounce check failed", "error", err)
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "internal error"), nil
	}

	if bounce {
		logger.Info("request denied by bouncer")
		return getDeniedResponse(envoy_type.StatusCode_Forbidden, "forbidden"), nil
	}
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: 0,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{},
	}, nil
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
