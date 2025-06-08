package logger

import (
	"context"
	"log/slog"
	"testing"
)

func TestLevelFromString(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected slog.Level
	}{
		{"debug level", "debug", slog.LevelDebug},
		{"info level", "info", slog.LevelInfo},
		{"warn level", "warn", slog.LevelWarn},
		{"error level", "error", slog.LevelError},
		{"default level", "invalid", slog.LevelInfo},
		{"case insensitive", "DEBUG", slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LevelFromString(tt.level); got != tt.expected {
				t.Errorf("LevelFromString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWithContext(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(nil, nil))

	newCtx := WithContext(ctx, logger)

	if got := newCtx.Value(loggerKey).(*slog.Logger); got != logger {
		t.Errorf("WithContext() stored logger = %v, want %v", got, logger)
	}
}

func TestFromContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, nil))

	tests := []struct {
		name string
		ctx  context.Context
		want *slog.Logger
	}{
		{
			name: "nil context",
			ctx:  nil,
		},
		{
			name: "context without logger",
			ctx:  context.Background(),
		},
		{
			name: "context with logger",
			ctx:  WithContext(context.Background(), logger),
			want: logger,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromContext(tt.ctx)
			if tt.want != nil && got != tt.want {
				t.Errorf("FromContext() = %v, want %v", got, tt.want)
			}
		})
	}
}
