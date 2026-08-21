package logger

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevelFromString(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{name: "debug level", level: "debug", want: slog.LevelDebug},
		{name: "info level", level: "info", want: slog.LevelInfo},
		{name: "warn level", level: "warn", want: slog.LevelWarn},
		{name: "error level", level: "error", want: slog.LevelError},
		{name: "unknown level falls back to info", level: "invalid", want: slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LevelFromString(tt.level)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, nil))

	newCtx := WithContext(t.Context(), logger)

	got, ok := newCtx.Value(loggerKey).(*slog.Logger)
	require.True(t, ok)
	assert.Same(t, logger, got)
}

func TestFromContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, nil))

	tests := []struct {
		name string
		ctx  context.Context
		want *slog.Logger
	}{
		{name: "nil context", ctx: nil, want: nil},
		{name: "context without logger", ctx: t.Context(), want: nil},
		{name: "context with logger", ctx: WithContext(t.Context(), logger), want: logger},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromContext(tt.ctx)

			if tt.want == nil {
				require.NotNil(t, got)
				return
			}

			assert.Same(t, tt.want, got)
		})
	}
}
