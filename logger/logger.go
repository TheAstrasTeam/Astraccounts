package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
)

type Options struct {
	Level  slog.Level
	Output io.Writer
}

func Init(opts *Options) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Output == nil {
		opts.Output = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{
		Level: opts.Level,
	}

	handler := newColorConsoleHandler(opts.Output, handlerOpts)
	l := slog.New(handler)

	slog.SetDefault(l)
}

func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

func With(args ...any) *slog.Logger {
	return slog.With(args...)
}
