package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	auth.UnimplementedAuthorizationServer
	remediator Remediator
	config     config.Config
	logger     *slog.Logger
}

func NewServer(config config.Config, remediator Remediator, logger *slog.Logger) *Server {
	return &Server{
		config:     config,
		remediator: remediator,
		logger:     logger,
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
	if s.remediator == nil {
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, "remediator not initialized"), nil
	}
	result := s.remediator.Check(ctx, req)
	switch result.Action {
	case "deny":
		return getDeniedResponse(envoy_type.StatusCode_Forbidden, result.Reason), nil
	case "error":
		return getDeniedResponse(envoy_type.StatusCode_InternalServerError, result.Reason), nil
	default:
		return &auth.CheckResponse{
			Status: &status.Status{
				Code: 0,
			},
			HttpResponse: &auth.CheckResponse_OkResponse{},
		}, nil
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
