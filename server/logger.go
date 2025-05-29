package server

import (
	"context"
	"io"
	"log/slog"
)

type ctxKey string

const loggerKey ctxKey = "logger"

// WithLogger returns a new context with the provided logger
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext gets a logger from context or returns a no-op logger
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
